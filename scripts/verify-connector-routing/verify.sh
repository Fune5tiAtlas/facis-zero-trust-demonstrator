#!/usr/bin/env bash
# Evidence for ZT-26 (BDD-ZT-026): application traffic crosses the zone boundary through the Zero Trust
# Connector's zone gateway only, and the declared bypasses (name resolution, observability export) work
# over their own paths (docs/architecture.md, "Zero Trust Connector routing"). Runs against a zone that is
# already installed, with the gateway release(s) of deployment/helm/connector-gateway in place; installs,
# upgrades and uninstalls nothing. Creates its stand-ins (fixtures/) and removes them on exit.
#
# Sections, each run when the zone has what it probes:
#   egress-route   (a gateway of the egress role in ROUTE_NAMESPACE) the admitted caller reaches the peer
#                  zone through the gateway, the gateway's access log records the request and its
#                  upstream (the peer read from the gateway's own NetworkPolicy, never from the caller),
#                  and PEER_LOG_CMD, when given, shows the request arriving at the peer; an impostor with
#                  the caller's labels and another identity is refused by the gateway's proxy (403 and a
#                  denial line naming it)
#   direct-path    the same caller's direct attempt at every DIRECT_EXTERNAL address (and at the peer
#                  entry, when there is a gateway) is dropped by the network layer (Hubble's policy drop
#                  cited when the node's agent answers), and the peer never logs it; every DIRECT_TARGETS
#                  Service of the zone (namespace/name:port) is unreachable from the caller as well
#   entry          (ENTRY_NAMESPACE and ENTRY_NAME) the zone's entry routes every request to its one
#                  upstream, and every Service of type LoadBalancer or NodePort in the cluster is the
#                  entry or one of DECLARED_ENTRIES (namespace/name): no other way into the zone
#   exemptions     DNS: the caller resolves a cluster name and the gateway's name through the resolver
#                  lane; observability export: the caller reaches the zone's collector (or a stand-in with
#                  the row's labels and identity) on 4318
#
# Usage: scripts/verify-connector-routing/verify.sh [--help]
# Exit status: 0 every check passed; 1-124 the number of failed checks; 125 refused or not run.
#
# Environment:
#   KUBE_CONTEXT       kind-<name>, or zerotrust-a / zerotrust-b with ZTD_CONFIRM_CLUSTER equal to it
#                      (scripts/lib/proof.sh, as the other cluster proofs)
#   ROUTE_NAMESPACE    the data-plane namespace of the caller and the gateway (default: the zone file's)
#   GATEWAY            the egress gateway's name (default ztd-connector-gateway; absent: no egress section)
#   ROUTE_METHOD, ROUTE_PATH, ROUTE_BODY, ROUTE_EXPECT
#                      the application request sent through the gateway (default GET /) and a string its
#                      response body must hold (default: none)
#   PEER_LOG_CMD       a command printing the peer entry's access log (kind: docker logs of the peer
#                      container; a zone: kubectl logs of the peer zone's entry), run before and after
#   DIRECT_EXTERNAL    space-separated <IPv4>:<port> outside the cluster the caller must not reach
#   DIRECT_TARGETS     space-separated <namespace>/<service>:<port> inside the zone the caller must not reach
#   ENTRY_NAMESPACE, ENTRY_NAME, DECLARED_ENTRIES   the entry section (see above)
#   ZTD_EVIDENCE_DIR   the run directory (default: a new one under ~/.local/state/ztd/verify-connector-routing)
# shellcheck disable=SC2016,SC1091,SC2319,SC2329,SC2086
set -uo pipefail
PROOF_NAME=verify-connector-routing
PROOF_OTHER_CONTEXT="the run creates stand-ins in the zone"
# shellcheck source=scripts/lib/proof.sh
. "$(dirname "$0")/../lib/proof.sh"
# shellcheck source=scripts/lib/probe.sh
. "$(dirname "$0")/../lib/probe.sh"
usage() { sed -n '2,/^# shellcheck/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
case $# in
  0) ;;
  *) case $1 in -h|--help) usage; exit 0;; esac; usage >&2; exit 125;;
esac
proof_refuse_ci
[ -n "${ZTD_EVIDENCE_DIR:-}" ] && ZTD_EVIDENCE_DIR=$(realpath -m -- "$ZTD_EVIDENCE_DIR")
cd "$(dirname "$0")" || exit 125
REPO=$(git rev-parse --show-toplevel)
CHART=$REPO/deployment/helm/ztd
CONTEXT=${KUBE_CONTEXT:-kind-ztd}
proof_guard_context
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
proof_run_dir verify-connector-routing
proof_run_dir_new
mkdir -p "$EVID" || exit 125
OUT=$EVID/evidence.md
WORK=$(mktemp -d)
failures=0
NS=${ROUTE_NAMESPACE:-$(yaml_get "$CHART/values.yaml" planes data namespace)}
MGMT=$(yaml_get "$CHART/values.yaml" planes management namespace)
TD=$(yaml_get "$ZONE_VALUES" zone trustDomain)
GW=${GATEWAY:-ztd-connector-gateway}
RUN=$(date -u +%Y%m%dT%H%M%SZ)-$$
UA="ztd-route/$RUN"
cleanup() {
  k -n "$NS" delete -f "$WORK/stand-ins.yaml" --ignore-not-found --wait=false >/dev/null 2>&1
  [ -f "$WORK/otel.yaml" ] && k -n "$MGMT" delete -f "$WORK/otel.yaml" --ignore-not-found --wait=false >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

say "# Zero Trust Connector routing (ZT-26) on $CONTEXT" '' \
  "Run $RUN, started $started, commit $(git rev-parse HEAD)$(git diff --quiet HEAD || echo ' (working tree modified)')." \
  "Zone file: ${ZONE_VALUES#"$REPO"/}; route namespace $NS; trust domain $TD."

section stand-ins
sed "s/__NS__/$NS/g" fixtures/stand-ins.yaml > "$WORK/stand-ins.yaml"
k apply -f "$WORK/stand-ins.yaml" >/dev/null
k -n "$NS" wait --for=condition=Ready pod/route-backend pod/route-impostor --timeout=180s >/dev/null
check $? "the caller (service account backend) and the impostor (route-impostor, same labels) are ready in $NS"
send() { # send <pod> <url> [curl args...]: HTTP code and the first body line, or denied(<exit>)
  local pod=$1 url=$2; shift 2
  local out; out=$(probe_exec -n "$NS" exec "$pod" -c app -- curl -sS -m 20 --connect-timeout 6 "$@" -w "\n%{http_code}\n$CURL_EXIT_FMT\n" "$url" 2>/dev/null)
  case $(curl_exit "$out") in
    7|28|35|52|56) echo "denied($(curl_exit "$out"))";;
    *) http_outcome "$out";;
  esac
}
peer_log() { [ -n "${PEER_LOG_CMD:-}" ] && bash -c "$PEER_LOG_CMD" 2>/dev/null; }
node=$(node_of "$NS" route-backend)
hubble_drops() { # hubble_drops <ip> <port>: the policy drops Hubble recorded from the caller to <ip>:<port>
  local C; C=$(cilium_on "$node")
  [ -n "$C" ] && k -n kube-system exec "$C" -c cilium-agent -- hubble observe --since 3m --from-pod "$NS/route-backend" \
    --to-ip "$1" --to-port "$2" --verdict DROPPED -o compact 2>/dev/null | grep -i policy
}

direct=${DIRECT_EXTERNAL:-}
if k -n "$NS" get deploy "$GW" >/dev/null 2>&1; then
  section egress-route
  pol=$(k -n "$NS" get networkpolicy "$GW" -o json)
  peer=$(jq -r '.spec.egress[0].to[0].ipBlock.cidr | sub("/32$"; "")' <<<"$pol")
  pport=$(jq -r '.spec.egress[0].ports[0].port' <<<"$pol")
  route=$(jq -r '.metadata.annotations["ztd.facis.io/connector-route"]' <<<"$pol")
  egress_rules=$(jq '.spec.egress | length' <<<"$pol")
  [ "$egress_rules" = 1 ] && [ -n "$peer" ] && [ "$peer" != null ]
  check $? "the gateway $GW ($route) has one egress lane, to the peer entry $peer:$pport" "$(jq -c .spec.egress <<<"$pol")"
  direct="$direct $peer:$pport"
  k -n "$NS" wait --for=condition=Available "deploy/$GW" --timeout=120s >/dev/null
  check $? "the gateway is available"
  gwpod=$(k -n "$NS" get pod -l "app.kubernetes.io/name=$GW" -o jsonpath='{.items[0].metadata.name}')
  peer_log > "$WORK/peer.before"
  args=(-A "$UA" -X "${ROUTE_METHOD:-GET}")
  [ -n "${ROUTE_BODY:-}" ] && args+=(-H 'Content-Type: application/json' --data "$ROUTE_BODY")
  # The whole body is read for ROUTE_EXPECT; the record keeps the outcome line only.
  raw=$(probe_exec -n "$NS" exec route-backend -c app -- curl -sS -m 20 "${args[@]}" -w "\n%{http_code}\n$CURL_EXIT_FMT\n" "http://$GW.$NS.svc.cluster.local:8080${ROUTE_PATH:-/}" 2>/dev/null)
  out=$(http_outcome "$raw")
  case $out in "200 "*) grep -qF -- "${ROUTE_EXPECT:-}" <<<"$raw"; ok=$?;; *) ok=1;; esac
  check $ok "the caller's ${ROUTE_METHOD:-GET} ${ROUTE_PATH:-/} through the gateway is served by the peer zone${ROUTE_EXPECT:+ (its response holds $ROUTE_EXPECT)}" "outcome: $out"
  # Envoy writes its access log to stdout in batches (about every 10 s): read again for up to 60 s.
  for _ in $(seq 12); do
    line=$(k -n "$NS" logs "$gwpod" -c envoy 2>/dev/null | grep -F "\"$UA\"" | tail -1)
    [ -n "$line" ] && break; sleep 5
  done
  jq -e --arg u "$peer:$pport" '(.status | tostring) == "200" and .upstream == $u' <<<"$line" >/dev/null 2>&1
  check $? "the gateway's access log records the request and its upstream, the peer entry" "$line"
  if [ -n "${PEER_LOG_CMD:-}" ]; then
    # The peer's log, batched the same way, is read again for up to 60 s.
    for _ in $(seq 12); do
      peer_log > "$WORK/peer.after"
      seen=$(diff "$WORK/peer.before" "$WORK/peer.after" | grep -F "\"$UA\"" | head -1)
      [ -n "$seen" ] && break; sleep 5
    done
    [ -n "$seen" ]
    check $? "the peer entry logs the request's arrival" "${seen#> }"
  else
    say "- n/a: the peer's log (PEER_LOG_CMD unset)"
  fi
  k -n "$NS" logs "$gwpod" -c istio-proxy > /dev/null 2>&1
  before=$(denial_lines "$NS" "$gwpod" | wc -l)
  out=$(send route-impostor "http://$GW.$NS.svc.cluster.local:8080/" -A "$UA-impostor")
  sleep 3
  imp="spiffe://$TD/ns/$NS/sa/route-impostor"
  deny=$(denial_lines "$NS" "$gwpod" | tail -n +"$((before + 1))" | grep -F "$imp" | head -1)
  case $out in 403*) [ -n "$deny" ];; *) false;; esac
  check $? "the impostor (same labels, identity route-impostor) is refused by the gateway's proxy" "outcome: $out; denial: ${deny:-none}"
fi

section direct-path
peer_log > "$WORK/peer.before"
for d in $direct; do
  ip=${d%:*}; port=${d##*:}
  out=$(send route-backend "https://$ip:$port/" -k -A "$UA-direct")
  drop=$(hubble_drops "$ip" "$port" | tail -1)
  if [ -n "$(cilium_on "$node")" ] && k -n kube-system exec "$(cilium_on "$node")" -c cilium-agent -- hubble status >/dev/null 2>&1; then
    case $out in denied*) [ -n "$drop" ];; *) false;; esac
    check $? "the caller's direct attempt at $d, around the gateway, is dropped by the network layer" "outcome: $out; Hubble: ${drop:-no policy drop recorded}"
  else
    case $out in denied*) true;; *) false;; esac
    check $? "the caller's direct attempt at $d, around the gateway, is dropped by the network layer" "outcome: $out (no Hubble on the node: the outcome's class is the evidence)"
  fi
done
if [ -n "${PEER_LOG_CMD:-}" ] && [ -n "$direct" ]; then
  sleep 60   # past the peer log's batching (above), so an arrival would show
  peer_log > "$WORK/peer.after"
  ! diff "$WORK/peer.before" "$WORK/peer.after" | grep -qF "$UA-direct"
  check $? "no direct attempt reached the peer entry (its log holds none)"
fi
for t in ${DIRECT_TARGETS:-}; do
  tns=${t%%/*}; rest=${t#*/}; svc=${rest%:*}; port=${rest##*:}
  out=$(send route-backend "http://$svc.$tns.svc.cluster.local:$port/" -A "$UA-direct")
  case $out in denied*|403*) true;; *) false;; esac
  check $? "the caller cannot reach $t directly" "outcome: $out"
done

if [ -n "${ENTRY_NAMESPACE:-}" ]; then
  section entry
  cfg=$(k -n "$ENTRY_NAMESPACE" get configmap "$ENTRY_NAME" -o json | jq -r '.data["envoy.yaml"] // .data["envoy.json"]')
  routes=$(python3 -c 'import sys,yaml
c=yaml.safe_load(sys.stdin)
for l in c["static_resources"]["listeners"]:
  for fc in l["filter_chains"]:
    for f in fc["filters"]:
      for vh in f["typed_config"]["route_config"]["virtual_hosts"]:
        for r in vh["routes"]: print(l["address"]["socket_address"]["port_value"], r["match"], r["route"]["cluster"])
for cl in c["static_resources"]["clusters"]:
  for e in cl["load_assignment"]["endpoints"]:
    for le in e["lb_endpoints"]: a=le["endpoint"]["address"]["socket_address"]; print("cluster", cl["name"], a["address"], a["port_value"])' <<<"$cfg")
  [ "$(grep -c '^cluster ' <<<"$routes")" = 1 ]
  check $? "the entry $ENTRY_NAMESPACE/$ENTRY_NAME forwards every request to one upstream" "$(paste -sd';' - <<<"$routes")"
  exposed=$(k get svc -A -o json | jq -r '.items[] | select(.spec.type == "LoadBalancer" or .spec.type == "NodePort") | "\(.metadata.namespace)/\(.metadata.name)"' | sort)
  extra=$(comm -23 <(printf '%s\n' "$exposed") <(printf '%s\n' "$ENTRY_NAMESPACE/$ENTRY_NAME" ${DECLARED_ENTRIES:-} | sort))
  [ -z "$extra" ] && grep -qx "$ENTRY_NAMESPACE/$ENTRY_NAME" <<<"$exposed"
  check $? "every Service exposed outside the cluster is the entry or a declared bypass" "exposed: $(paste -sd' ' - <<<"$exposed"); undeclared: ${extra:-none}"
fi

section exemptions
names="kubernetes.default.svc.cluster.local"
k -n "$NS" get svc "$GW" >/dev/null 2>&1 && names="$names $GW.$NS.svc.cluster.local"
out=$(probe_exec -n "$NS" exec route-backend -c app -- sh -c "for n in $names; do nslookup \$n >/dev/null || exit 1; done; echo curl-exit=0" 2>/dev/null)
[ -n "$(curl_exit "$out")" ] || out="curl-exit=1"
[ "$(curl_exit "$out")" = 0 ]
check $? "DNS (declared bypass, name resolution): the caller resolves cluster names through the resolver lane" "names: $names"
if [ -z "$(k -n "$MGMT" get pod -l app.kubernetes.io/name=otel-collector --field-selector=status.phase=Running -o name 2>/dev/null)" ]; then
  sed "s/__NS__/$MGMT/g" fixtures/otel-stand-in.yaml > "$WORK/otel.yaml"
  k apply -f "$WORK/otel.yaml" >/dev/null && k -n "$MGMT" wait --for=condition=Ready pod/route-otel-stand-in --timeout=180s >/dev/null
  target="http://route-otel-stand-in.$MGMT.svc.cluster.local:4318/"; what="a stand-in with the row's labels and identity"
else
  ip=$(k -n "$MGMT" get pod -l app.kubernetes.io/name=otel-collector -o jsonpath='{.items[0].status.podIP}')
  target="http://$ip:4318/"; what="the zone's collector"
fi
out=$(send route-backend "$target" -A "$UA-otel")
case $out in denied*|error*|403*) false;; *) true;; esac
check $? "observability export (declared bypass, ZT-26): the caller reaches $what on 4318 in $MGMT" "outcome: $out"

say '' "Result: $failures failed check(s)."
if [ "$CLUSTER_KIND" = provider ]; then proof_mask "$OUT" > "$OUT.masked" && mv "$OUT.masked" "$OUT"; fi
echo "$EVID"
proof_exit
