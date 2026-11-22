#!/usr/bin/env bash
# Evidence for ZT-26 (BDD-ZT-026): application traffic crosses the zone boundary through the Zero Trust
# Connector's zone gateway only, and the declared bypasses (name resolution, observability export) work
# over their own paths (docs/architecture.md, "Zero Trust Connector routing"). Runs against a zone that is
# already installed, with the release of deployment/helm/connector-gateway its ROLE names; installs,
# upgrades and uninstalls nothing. Creates its stand-ins (fixtures/) and removes on exit exactly what it
# created: a service account that already exists is used and left in place.
#
# ROLE (required) names what the zone holds; every section of that role is mandatory, and a missing
# release, policy or target fails the run instead of skipping a section:
#   egress   the gateway GATEWAY in ROUTE_NAMESPACE. egress-route: its lane out of the cluster is the one
#            CiliumNetworkPolicy <gateway>-peer, bound to the gateway's service account; the admitted
#            caller reaches the peer zone through it, the gateway's access log records the request and
#            its upstream, PEER_LOG_CMD shows it arriving at the peer; an impostor with the caller's labels
#            is refused by the gateway's proxy (403 and a denial line naming it); a pod carrying the
#            gateway's own label under another identity gets no lane out (Hubble's policy drop).
#   ingress  the entry ENTRY_NAME in ENTRY_NAMESPACE. entry: it forwards every request to one upstream,
#            and every Service of type LoadBalancer or NodePort in the cluster is the entry or one of
#            DECLARED_ENTRIES (namespace/name); every declared entry needs at least one DECLARED_PROBES
#            line, sent from the proof host (outside the cluster) to the Service's load-balancer address, so
#            a declared entry is held to its scope, never passed silently. DIRECT_TARGETS and
#            DIRECT_EXTERNAL are required.
# Both roles: direct-path, the caller's attempt at the peer entry (egress), at every DIRECT_EXTERNAL and
# every DIRECT_TARGETS is denied, with evidence: a network denial counts only with the policy drop Hubble
# recorded for the flow (no Hubble on the node fails the check), a mesh denial only with the destination
# proxy's denial line; each target names its protocol and is sent a valid request of it (HTTPS to a TLS
# listener). exemptions: DNS resolution, and the observability export to the collector (or a stand-in
# with the row's labels and identity) on 4318.
#
# Usage: scripts/verify-connector-routing/verify.sh [--help]
# Exit status: 0 every check passed; 1-124 the number of failed checks; 125 refused or not run.
#
# Environment:
#   KUBE_CONTEXT       kind-<name>, or zerotrust-a / zerotrust-b with ZTD_CONFIRM_CLUSTER equal to it
#                      (scripts/lib/proof.sh, as the other cluster proofs)
#   ROLE               egress | ingress (required)
#   ROUTE_NAMESPACE    the data-plane namespace of the caller (and of the gateway; default: the zone file's)
#   GATEWAY            the egress gateway's name (default ztd-connector-gateway)
#   ROUTE_METHOD, ROUTE_PATH, ROUTE_BODY, ROUTE_EXPECT
#                      the application request sent through the gateway (default GET /) and a string its
#                      response body must hold (default: none)
#   PEER_LOG_CMD       egress: a command printing the peer entry's access log (required)
#   DIRECT_EXTERNAL    space-separated <IPv4>:<port>/<http|https> outside the cluster the caller must not reach
#   DIRECT_TARGETS     space-separated <namespace>/<service>:<port>/<http|https> inside the zone
#   ENTRY_NAMESPACE, ENTRY_NAME, DECLARED_ENTRIES   the entry section (see above)
#   DECLARED_PROBES    one line per scope assertion of a declared entry, fields separated by |:
#                        <ns>/<svc>|https|<METHOD> <host> <path>|<code, or !2xx>
#                        <ns>/<svc>|tls12|<host>|refused        (TLS 1.2 handshake refused)
#                        <ns>/<svc>|dns|<qname> <type>|<rcode>  (UDP and TCP)
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
nogo() { echo "$PROOF_NAME: $*" >&2; exit 125; }
target_ok() { [[ $1 =~ ^[^/]+/[^:]+:[0-9]+/(http|https)$ ]]; }
external_ok() { [[ $1 =~ ^[0-9.]+:[0-9]+/(http|https)$ ]]; }
case ${ROLE:-} in
  egress) [ -n "${PEER_LOG_CMD:-}" ] || nogo "ROLE=egress needs PEER_LOG_CMD (the peer's arrival is part of the proof)";;
  ingress) [ -n "${ENTRY_NAMESPACE:-}" ] && [ -n "${ENTRY_NAME:-}" ] && [ -n "${DIRECT_TARGETS:-}" ] && [ -n "${DIRECT_EXTERNAL:-}" ] \
             || nogo "ROLE=ingress needs ENTRY_NAMESPACE, ENTRY_NAME, DIRECT_TARGETS and DIRECT_EXTERNAL";;
  *) nogo "ROLE must be egress or ingress";;
esac
for t in ${DIRECT_TARGETS:-}; do target_ok "$t" || nogo "DIRECT_TARGETS entry '$t' is not <namespace>/<service>:<port>/<http|https>"; done
for t in ${DIRECT_EXTERNAL:-}; do external_ok "$t" || nogo "DIRECT_EXTERNAL entry '$t' is not <IPv4>:<port>/<http|https>"; done
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
CREATED=$WORK/created
: >"$CREATED"
failures=0
NS=${ROUTE_NAMESPACE:-$(yaml_get "$CHART/values.yaml" planes data namespace)}
MGMT=$(yaml_get "$CHART/values.yaml" planes management namespace)
TD=$(yaml_get "$ZONE_VALUES" zone trustDomain)
GW=${GATEWAY:-ztd-connector-gateway}
RUN=$(date -u +%Y%m%dT%H%M%SZ)-$$
UA="ztd-route/$RUN"
# Only what this run created is removed: one "<namespace> <kind> <name>" line per object, in $CREATED.
cleanup() {
  awk '{l[NR]=$0} END {for (i = NR; i > 0; i--) print l[i]}' "$CREATED" 2>/dev/null | while read -r ns kind name; do
    k -n "$ns" delete "$kind" "$name" --ignore-not-found --timeout=120s >/dev/null 2>&1   # gone before the next run
  done
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ensure_sa() { # ensure_sa <ns> <name>: an existing service account is used as it is
  k -n "$1" get serviceaccount "$2" >/dev/null 2>&1 && { echo "$1 serviceaccount $2 (existing, kept)" >>"$WORK/kept"; return 0; }
  k -n "$1" create serviceaccount "$2" >/dev/null && k -n "$1" label serviceaccount "$2" app.kubernetes.io/part-of=verify-connector-routing >/dev/null \
    && echo "$1 serviceaccount $2" >>"$CREATED"
}
create() { # create <ns> <file>: every object of the file, each recorded once created; refuses one that exists
  local f=$2 n
  for n in $(k create -f "$f" -o name 2>"$WORK/create.err"); do echo "$1 ${n%%/*} ${n#*/}" >>"$CREATED"; done
  [ ! -s "$WORK/create.err" ]
}

say "# Zero Trust Connector routing (ZT-26) on $CONTEXT, role $ROLE" '' \
  "Run $RUN, started $started, commit $(git rev-parse HEAD)$(git diff --quiet HEAD || echo ' (working tree modified)')." \
  "Zone file: ${ZONE_VALUES#"$REPO"/}; route namespace $NS; trust domain $TD."

section stand-ins
ensure_sa "$NS" backend && ensure_sa "$NS" route-impostor
sed "s/__NS__/$NS/g" fixtures/stand-ins.yaml >"$WORK/stand-ins.yaml"
create "$NS" "$WORK/stand-ins.yaml" && k -n "$NS" wait --for=condition=Ready pod/route-backend pod/route-impostor --timeout=180s >/dev/null
check $? "the caller (service account backend) and the impostor (route-impostor, same labels) are ready in $NS" \
  "$(cat "$WORK/create.err" 2>/dev/null)$( [ -s "$WORK/kept" ] && echo "; used as found: $(paste -sd';' - <"$WORK/kept")")"
send() { # send <pod> <url> [curl args...]: HTTP code and the first body line, or denied(<exit>)
  local pod=$1 url=$2; shift 2
  local out; out=$(probe_exec -n "$NS" exec "$pod" -c app -- curl -sS -m 20 --connect-timeout 6 "$@" -w "\n%{http_code}\n$CURL_EXIT_FMT\n" "$url" 2>/dev/null)
  case $(curl_exit "$out") in
    7|28|35|52|56) echo "denied($(curl_exit "$out"))";;
    *) http_outcome "$out";;
  esac
}
url() { # url <host> <port> <proto>: a valid request of the target's protocol (no certificate check: only the path is tested)
  echo "$3://$1:$2/"
}
peer_log() { bash -c "$PEER_LOG_CMD" 2>/dev/null; }
hubble_on() { local C; C=$(cilium_on "$(node_of "$NS" "$1")"); [ -n "$C" ] && k -n kube-system exec "$C" -c cilium-agent -- hubble status >/dev/null 2>&1; }
hubble_drop() { # hubble_drop <pod> <pattern>: the last policy drop Hubble recorded from <pod> to a destination matching <pattern>
  local C; C=$(cilium_on "$(node_of "$NS" "$1")")
  [ -n "$C" ] && k -n kube-system exec "$C" -c cilium-agent -- hubble observe --since 3m --from-pod "$NS/$1" \
    --verdict DROPPED -o compact 2>/dev/null | grep -i policy | grep -F -- "$2" | tail -1
}
denied_by_network() { # denied_by_network <pod> <outcome> <pattern> <title>: a drop with Hubble's policy drop
  local pod=$1 out=$2 pattern=$3 title=$4 drop
  if ! hubble_on "$pod"; then check 1 "$title" "outcome: $out; no Hubble on the node: no evidence of a policy drop"; return; fi
  drop=$(hubble_drop "$pod" "$pattern")
  case $out in denied*) [ -n "$drop" ];; *) false;; esac
  check $? "$title" "outcome: $out; Hubble: ${drop:-no policy drop recorded}"
}

direct=${DIRECT_EXTERNAL:-}
if [ "$ROLE" = egress ]; then
  section egress-route
  if ! k -n "$NS" get deploy "$GW" >/dev/null 2>"$WORK/gw.err"; then
    check 1 "the egress gateway $GW exists in $NS" "$(head -1 "$WORK/gw.err")"
  else
    cnp=$(k -n "$NS" get ciliumnetworkpolicy "$GW-peer" -o json 2>/dev/null)
    peer=$(jq -r '.spec.egress[0].toCIDR[0] // empty | sub("/32$"; "")' <<<"$cnp" 2>/dev/null)
    pport=$(jq -r '.spec.egress[0].toPorts[0].ports[0].port // empty' <<<"$cnp" 2>/dev/null)
    sa=$(jq -r '.spec.endpointSelector.matchLabels["io.cilium.k8s.policy.serviceaccount"] // empty' <<<"$cnp" 2>/dev/null)
    lanes=$(k -n "$NS" get networkpolicy -o json | jq '[.items[] | select(.metadata.annotations["ztd.facis.io/connector-route"] != null) | (.spec.egress // [])[]] | length')
    [ -n "$peer" ] && [ -n "$pport" ] && [ "$sa" = "$GW" ] && [ "$(jq '.spec.egress | length' <<<"$cnp")" = 1 ] && [ "$lanes" = 0 ]
    check $? "the gateway's one lane out of the cluster is $GW-peer, bound to its service account, to the peer entry $peer:$pport" \
      "endpoint selector: service account ${sa:-none}; route NetworkPolicies with an egress rule: $lanes"
    direct="$direct $peer:$pport/https"
    k -n "$NS" wait --for=condition=Available "deploy/$GW" --timeout=120s >/dev/null
    check $? "the gateway is available"
    gwpod=$(k -n "$NS" get pod -l "app.kubernetes.io/name=$GW,pod-template-hash" -o jsonpath='{.items[0].metadata.name}')
    peer_log >"$WORK/peer.before"
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
    for _ in $(seq 12); do
      peer_log >"$WORK/peer.after"
      seen=$(diff "$WORK/peer.before" "$WORK/peer.after" | grep -F "\"$UA\"" | head -1)
      [ -n "$seen" ] && break; sleep 5
    done
    [ -n "$seen" ]
    check $? "the peer entry logs the request's arrival" "${seen#> }"
    before=$(denial_lines "$NS" "$gwpod" | wc -l)
    out=$(send route-impostor "http://$GW.$NS.svc.cluster.local:8080/" -A "$UA-impostor")
    sleep 3
    imp="spiffe://$TD/ns/$NS/sa/route-impostor"
    deny=$(denial_lines "$NS" "$gwpod" | tail -n +"$((before + 1))" | grep -F "$imp" | head -1)
    case $out in 403*) [ -n "$deny" ];; *) false;; esac
    check $? "the impostor (same labels, identity route-impostor) is refused by the gateway's proxy" "outcome: $out; denial: ${deny:-none}"
    # A pod with the gateway's own label and another identity: the lane is the service account's, not the label's.
    sed -e "s/__NS__/$NS/g" -e "s/__GW__/$GW/g" fixtures/gateway-spoof.yaml >"$WORK/spoof.yaml"
    if create "$NS" "$WORK/spoof.yaml"; then
      for _ in $(seq 60); do k -n "$NS" exec route-gateway-spoof -c app -- true >/dev/null 2>&1 && break; sleep 3; done
      out=$(send route-gateway-spoof "$(url "$peer" "$pport" https)" -k -A "$UA-spoof")
      denied_by_network route-gateway-spoof "$out" "$peer:$pport" "a pod carrying the gateway's label under another identity gets no lane to the peer entry"
    else
      check 1 "a pod carrying the gateway's label under another identity gets no lane to the peer entry" "$(cat "$WORK/create.err")"
    fi
  fi
fi

section direct-path
[ "$ROLE" = egress ] && peer_log >"$WORK/peer.before"
for d in $direct; do
  hp=${d%/*}; proto=${d##*/}; ip=${hp%:*}; port=${hp##*:}
  out=$(send route-backend "$(url "$ip" "$port" "$proto")" -k -A "$UA-direct")
  denied_by_network route-backend "$out" "$ip:$port" "the caller's direct $proto attempt at $hp, around the gateway, is dropped by the network layer"
done
if [ "$ROLE" = egress ]; then
  sleep 60   # past the peer log's batching (above), so an arrival would show
  peer_log >"$WORK/peer.after"
  ! diff "$WORK/peer.before" "$WORK/peer.after" | grep -qF -e "$UA-direct" -e "$UA-spoof"
  check $? "no direct attempt reached the peer entry (its log holds none)"
fi
for t in ${DIRECT_TARGETS:-}; do
  tns=${t%%/*}; rest=${t#*/}; proto=${rest##*/}; rest=${rest%/*}; svc=${rest%:*}; port=${rest##*:}
  if ! k -n "$tns" get svc "$svc" >/dev/null 2>&1; then check 1 "the caller cannot reach $t directly" "no such Service"; continue; fi
  sel=$(k -n "$tns" get svc "$svc" -o json | jq -r '.spec.selector | to_entries | map("\(.key)=\(.value)") | join(",")')
  pods=$(k -n "$tns" get pod -l "$sel" -o jsonpath='{.items[*].metadata.name}')
  for p in $pods; do denial_lines "$tns" "$p" | wc -l; done >"$WORK/before.$svc"
  out=$(send route-backend "$(url "$svc.$tns.svc.cluster.local" "$port" "$proto")" -k -A "$UA-direct")
  case $out in
    403*) sleep 3; caller="spiffe://$TD/ns/$NS/sa/backend"; deny=""
          i=0; for p in $pods; do i=$((i+1)); n=$(sed -n "${i}p" "$WORK/before.$svc")
            deny=$(denial_lines "$tns" "$p" | tail -n +"$((n + 1))" | grep -F "$caller" | head -1); [ -n "$deny" ] && break; done
          [ -n "$deny" ]; check $? "the caller cannot reach $t directly (refused by the destination's proxy)" "outcome: $out; denial: ${deny:-none}";;
    *) denied_by_network route-backend "$out" "$tns/" "the caller cannot reach $t directly (dropped by the network layer)";;
  esac
done

if [ "$ROLE" = ingress ]; then
  section entry
  cfg=$(k -n "$ENTRY_NAMESPACE" get configmap "$ENTRY_NAME" -o json 2>/dev/null | jq -r '.data["envoy.yaml"] // empty')
  routes=$(python3 -c 'import sys,yaml
c=yaml.safe_load(sys.stdin)
for l in c["static_resources"]["listeners"]:
  for fc in l["filter_chains"]:
    for f in fc["filters"]:
      for vh in f["typed_config"]["route_config"]["virtual_hosts"]:
        for r in vh["routes"]: print(l["address"]["socket_address"]["port_value"], r["match"], r["route"]["cluster"])
for cl in c["static_resources"]["clusters"]:
  for e in cl["load_assignment"]["endpoints"]:
    for le in e["lb_endpoints"]: a=le["endpoint"]["address"]["socket_address"]; print("cluster", cl["name"], a["address"], a["port_value"])' <<<"$cfg" 2>/dev/null)
  [ "$(grep -c '^cluster ' <<<"$routes")" = 1 ]
  check $? "the entry $ENTRY_NAMESPACE/$ENTRY_NAME forwards every request to one upstream" "$(paste -sd';' - <<<"$routes")"
  exposed=$(k get svc -A -o json | jq -r '.items[] | select(.spec.type == "LoadBalancer" or .spec.type == "NodePort") | "\(.metadata.namespace)/\(.metadata.name)"' | sort)
  extra=$(comm -23 <(printf '%s\n' "$exposed") <(printf '%s\n' "$ENTRY_NAMESPACE/$ENTRY_NAME" ${DECLARED_ENTRIES:-} | sort))
  [ -z "$extra" ] && grep -qx "$ENTRY_NAMESPACE/$ENTRY_NAME" <<<"$exposed"
  check $? "every Service exposed outside the cluster is the entry or a declared bypass" "exposed: $(paste -sd' ' - <<<"$exposed"); undeclared: ${extra:-none}"
  # A declared entry is held to its declared scope, probed from outside the cluster (this host).
  for e in ${DECLARED_ENTRIES:-}; do
    lb=$(k -n "${e%%/*}" get svc "${e#*/}" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)
    n=0
    while IFS='|' read -r who kind arg want; do
      [ "$who" = "$e" ] || continue; n=$((n+1))
      case $kind in
        https) read -r m host path <<<"$arg"
               got=$(curl -sk --resolve "$host:443:$lb" -o /dev/null -w '%{http_code}' -X "$m" -m 10 "https://$host$path")
               case $want in '!2xx') [[ $got != 2* && $got != 000 ]];; *) [ "$got" = "$want" ];; esac
               check $? "declared entry $e: $m $path answers $want" "answered $got";;
        tls12) curl -sk --resolve "$arg:443:$lb" --tls-max 1.2 -o /dev/null -m 10 "https://$arg/"; rc=$?
               [ "$rc" = 35 ]; check $? "declared entry $e: a TLS 1.2 handshake is refused" "curl exit $rc";;
        dns)   read -r q t <<<"$arg"
               u=$(dig @"$lb" "$q" "$t" +noall +comments +time=5 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
               c=$(dig @"$lb" "$q" "$t" +tcp +noall +comments +time=5 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
               [ "$u" = "$want" ] && [ "$c" = "$want" ]; check $? "declared entry $e: $q $t answers $want over UDP and TCP" "UDP ${u:-none}, TCP ${c:-none}";;
        *)     check 1 "declared entry $e: unknown probe kind $kind";;
      esac
    done <<<"${DECLARED_PROBES:-}"
    [ "$n" -gt 0 ]; check $? "declared entry $e is held to a declared scope" "$n scope assertion(s)"
  done
fi

section exemptions
names="kubernetes.default.svc.cluster.local"
[ "$ROLE" = egress ] && names="$names $GW.$NS.svc.cluster.local"
out=$(probe_exec -n "$NS" exec route-backend -c app -- sh -c "for n in $names; do nslookup \$n >/dev/null || exit 1; done; echo curl-exit=0" 2>/dev/null)
[ -n "$(curl_exit "$out")" ] || out="curl-exit=1"
[ "$(curl_exit "$out")" = 0 ]
check $? "DNS (declared bypass, name resolution): the caller resolves cluster names through the resolver lane" "names: $names"
if [ -z "$(k -n "$MGMT" get pod -l app.kubernetes.io/name=otel-collector --field-selector=status.phase=Running -o name 2>/dev/null)" ]; then
  ensure_sa "$MGMT" otel-collector
  sed "s/__NS__/$MGMT/g" fixtures/otel-stand-in.yaml >"$WORK/otel.yaml"
  create "$MGMT" "$WORK/otel.yaml" && k -n "$MGMT" wait --for=condition=Ready pod/route-otel-stand-in --timeout=180s >/dev/null
  target="http://route-otel-stand-in.$MGMT.svc.cluster.local:4318/"; what="a stand-in with the row's labels and identity"
else
  ip=$(k -n "$MGMT" get pod -l app.kubernetes.io/name=otel-collector -o jsonpath='{.items[0].status.podIP}')
  target="http://$ip:4318/"; what="the zone's collector"
fi
out=$(send route-backend "$target" -A "$UA-otel")
case $out in denied*|error*|403*) false;; *) true;; esac
check $? "observability export (declared bypass, ZT-26): the caller reaches $what on 4318 in $MGMT" "outcome: $out"
[ -s "$WORK/kept" ] && say '' "Existing objects used and left in place: $(paste -sd';' - <"$WORK/kept")."
say '' "Objects this run created (removed on exit): $(awk '{print $1"/"$2"/"$3}' "$CREATED" | paste -sd' ' -)."

say '' "Result: $failures failed check(s)."
if [ "$CLUSTER_KIND" = provider ]; then proof_mask "$OUT" >"$OUT.masked" && mv "$OUT.masked" "$OUT"; fi
echo "$EVID"
proof_exit
