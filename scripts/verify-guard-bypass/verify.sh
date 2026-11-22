#!/usr/bin/env bash
# Guard bypass proof on a live zone (FZTD-103). First a guarded call that succeeds end to end (the
# zone's public Participant route: Participant -> guard -> resource), then direct calls to the
# protected resource that skip the guard, each refused by the resource's own sidecar, with the
# receiver-side evidence read from that sidecar (its RBAC and listener counters before and after,
# and its access log), not inferred from a client-side failure.
#
# The direct callers are two short-lived probe Jobs, never Service endpoints (their readiness never
# passes). Both carry the guard's pod label, which is the only opening: the resource's network policy
# admits the guard's label on the resource port, so the packet reaches the receiver and the mesh
# decides. One is meshed under the Participant's service account (a valid mesh identity that is not
# the guard's: the resource's AuthorizationPolicy refuses it); the other has no sidecar (plaintext to a
# STRICT receiver). Nothing else is created or changed; the Jobs are deleted on exit and their absence
# is verified.
#
#   ZTD_CONFIRM_CONTEXT=<context> scripts/verify-guard-bypass/verify.sh --namespace NS --url URL --ca CA
#       --probe-image IMAGE --out DIR [--node NODE]
#
# IMAGE is an admitted image with bash (the probe speaks HTTP over /dev/tcp). Exit status: the number
# of failed checks; 125 refused.
set -euo pipefail

ns="" url="" ca="" image="" out="" node=""
while [ $# -gt 0 ]; do
  case "$1" in
    --namespace) ns=$2; shift 2 ;;
    --url) url=$2; shift 2 ;;
    --ca) ca=$2; shift 2 ;;
    --probe-image) image=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --node) node=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 125 ;;
  esac
done
context=$(kubectl config current-context)
if [ -z "$ns" ] || [ -z "$url" ] || [ ! -f "$ca" ] || [ -z "$image" ] || [ -z "$out" ] || [ "${ZTD_CONFIRM_CONTEXT:-}" != "$context" ]; then
  echo "refused: namespace, url, ca, probe image, out and ZTD_CONFIRM_CONTEXT=$context are required" >&2; exit 125
fi
[ ! -e "$out" ] || { echo "refused: $out exists" >&2; exit 125; }
mkdir -p "$out/before" "$out/after"
run=$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')
k() { kubectl -n "$ns" "$@"; }
failures=0
pass() { echo "PASS  $*" | tee -a "$out/verdict.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/verdict.txt"; failures=$((failures + 1)); }
cleanup() {
  k delete job -l "ztd.facis.io/probe-run=$run" --wait=true --timeout=120s >/dev/null 2>&1 || true
  k wait --for=delete pod -l "ztd.facis.io/probe-run=$run" --timeout=120s >/dev/null 2>&1 || true
  if [ -z "$(k get job,pod -l "ztd.facis.io/probe-run=$run" -o name 2>/dev/null)" ]; then
    echo "PASS  cleanup: no probe Job or Pod of run $run remains" | tee -a "$out/verdict.txt"
  else
    echo "FAIL  cleanup: probe objects of run $run remain" | tee -a "$out/verdict.txt"
  fi
}
trap cleanup EXIT

# The state the proof must leave as it found: every policy object and workload of the namespace.
snapshot() {
  k get authorizationpolicy,peerauthentication,networkpolicy,deployment,service -o json \
    | jq '[.items[] | {kind, name: .metadata.name, resourceVersion: .metadata.resourceVersion, generation: .metadata.generation}]' > "$1/objects.json"
  helm list -n "$ns" -o json | jq '[.[] | {name, revision, status, chart}]' > "$1/releases.json"
}
resource_pod=$(k get pod -l app.kubernetes.io/name=ztd-protected-resource -o jsonpath='{.items[0].metadata.name}')
stats() {
  k exec "$resource_pod" -c istio-proxy -- pilot-agent request GET stats 2>/dev/null \
    | grep -E '^(http\.inbound_0\.0\.0\.0_8080;\.rbac\.|listener\.0\.0\.0\.0_15006\.(no_filter_chain_match|downstream_cx_total|server_ssl_socket_factory)|listener\.0\.0\.0\.0_15006\.ssl\.connection_error)' \
    | sort > "$1"
}
snapshot "$out/before"
k get authorizationpolicy ztd-protected-resource-caller -o json | jq '{spec}' > "$out/before/resource-authorizationpolicy.json"
k get networkpolicy -o json | jq '[.items[] | select(.spec.podSelector.matchLabels["app.kubernetes.io/name"] == "ztd-protected-resource") | {name: .metadata.name, spec}]' > "$out/before/resource-networkpolicies.json"
{ echo "context: $context"; echo "namespace: $ns"; echo "uid: $(k get ns "$ns" -o jsonpath='{.metadata.uid}' 2>/dev/null || kubectl get ns "$ns" -o jsonpath='{.metadata.uid}')"; echo "resource pod: $resource_pod"; echo "probe run: $run"; echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; } > "$out/run.txt"

echo "== 1. The guarded path succeeds"
pub() { curl -sS -m 30 --cacert "$ca" -H 'Content-Type: application/json' "$@"; }
pub -X POST --data '{}' "$url/reset" > "$out/reset.json" || true
for _ in $(seq 1 60); do
  state=$(pub "$url/state" | jq -r '.state // empty' 2>/dev/null || true)
  [ "$state" = ready ] && break
  sleep 2
done
pub -X POST --data '{"resource":"sample-report","action":"read"}' "$url/demo" \
  | jq '{outcome, reasonCode, requestId, correlationId}' > "$out/guarded.json" || true
guarded_id=$(jq -r '.requestId // empty' "$out/guarded.json")
if [ "$(jq -r .outcome "$out/guarded.json")" = success ] && [ -n "$guarded_id" ]; then
  pass "guarded: $url/demo succeeds through the guard (request $guarded_id)"
else
  fail "guarded: $(cat "$out/guarded.json")"
fi
sleep 3
k logs deploy/ztd-guard -c guard --since=10m 2>/dev/null | grep -F "$guarded_id" > "$out/guarded-guard-record.jsonl" || true
k logs "$resource_pod" -c ztd-protected-resource --since=10m 2>/dev/null | grep -F "$guarded_id" > "$out/guarded-resource-record.jsonl" || true
if [ -s "$out/guarded-resource-record.jsonl" ]; then pass "guarded: the resource recorded request $guarded_id, the id the guard assigned"; else fail "guarded: the resource has no record of $guarded_id"; fi

echo "== 2. Direct calls to the resource, skipping the guard"
probe_job() { # probe_job NAME MESHED
  local inject='"sidecar.istio.io/nativeSidecar": "true"'
  [ "$2" = yes ] || inject='"sidecar.istio.io/inject": "false"'
  k apply -f - <<EOF >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: $1
  labels: {ztd.facis.io/probe-run: "$run"}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 600
  ttlSecondsAfterFinished: 60
  template:
    metadata:
      labels: {app.kubernetes.io/name: ztd-guard, spiffe.io/spire-managed-identity: "true", ztd.facis.io/probe: "true", ztd.facis.io/probe-run: "$run"}
      annotations: {$inject}
    spec:
      serviceAccountName: ztd-participant
      automountServiceAccountToken: false
      restartPolicy: Never
      ${node:+nodeSelector: {kubernetes.io/hostname: $node}}
      securityContext: {runAsNonRoot: true, runAsUser: 70, runAsGroup: 70, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: probe
          image: "$image"
          command: [/bin/bash, -c, "trap 'exit 0' TERM; while :; do sleep 10 & wait \$!; done"]
          readinessProbe: {exec: {command: [/bin/sh, -c, "exit 1"]}}
          resources: {requests: {cpu: 10m, memory: 32Mi}, limits: {memory: 128Mi}}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
EOF
}
attempt() { # attempt JOB OUT: POST /demo to the resource's Service from the probe, raw HTTP
  local raw='POST /demo HTTP/1.1\r\nHost: ztd-protected-resource:8080\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}'
  k exec "job/$1" -c probe -- timeout 15 /bin/bash -c "exec 3<>/dev/tcp/ztd-protected-resource/8080 && printf '$raw' >&3 && cat <&3" > "$2" 2>&1 || true
}
started() { [ "$(k get pod -l "job-name=$1" -o jsonpath='{.items[0].status.containerStatuses[?(@.name=="probe")].started}' 2>/dev/null)" = true ]; }
wait_started() { for _ in $(seq 1 90); do started "$1" && return 0; sleep 2; done; return 1; }
probes_from=$(date -u +%Y-%m-%dT%H:%M:%SZ)
for probe in meshed unmeshed; do
  name="ztd-bypass-$probe-$run"
  meshed=no; [ "$probe" = meshed ] && meshed=yes
  if ! probe_job "$name" "$meshed" 2> "$out/$probe-apply.txt"; then
    fail "$probe probe: not created: $(tr '\n' ' ' < "$out/$probe-apply.txt")"; continue
  fi
  if ! wait_started "$name"; then
    k get events --field-selector "involvedObject.kind=Job,involvedObject.name=$name" -o json | jq '[.items[] | {reason, message}]' > "$out/$probe-events.json"
    k get pod -l "job-name=$name" -o json | jq '[.items[] | .status]' > "$out/$probe-pod-status.json"
    fail "$probe probe: never started (events in $probe-events.json)"; continue
  fi
  stats "$out/$probe-stats-before.txt"
  attempt "$name" "$out/$probe-response.txt"
  sleep 3
  stats "$out/$probe-stats-after.txt"
  k logs "$resource_pod" -c istio-proxy --since=2m 2>/dev/null | grep -E '"response_code":"?403|rbac_access_denied|filter_chain_not_found|NR ' > "$out/$probe-receiver-log.txt" || true
  diff "$out/$probe-stats-before.txt" "$out/$probe-stats-after.txt" > "$out/$probe-stats-diff.txt" || true
done
b=$(grep 'http.inbound_0.0.0.0_8080;.rbac.denied' "$out/meshed-stats-before.txt" 2>/dev/null | awk -F': ' '{print $2}')
a=$(grep 'http.inbound_0.0.0.0_8080;.rbac.denied' "$out/meshed-stats-after.txt" 2>/dev/null | awk -F': ' '{print $2}')
if grep -q 'RBAC: access denied' "$out/meshed-response.txt" 2>/dev/null && [ -n "$a" ] && [ "$a" -gt "${b:-0}" ]; then
  pass "meshed direct call (Participant identity): 403 RBAC: access denied; the resource's sidecar counted it (rbac.denied $b -> $a)"
else
  fail "meshed direct call: response $(head -c 200 "$out/meshed-response.txt" 2>/dev/null | tr '\r\n' '  '), rbac.denied ${b:-?} -> ${a:-?}"
fi
if [ -f "$out/unmeshed-stats-diff.txt" ]; then
  nb=$(grep 'no_filter_chain_match' "$out/unmeshed-stats-before.txt" | awk -F': ' '{print $2}')
  na=$(grep 'no_filter_chain_match' "$out/unmeshed-stats-after.txt" | awk -F': ' '{print $2}')
  if ! grep -q '^HTTP/1.1 200' "$out/unmeshed-response.txt" && [ -s "$out/unmeshed-stats-diff.txt" ]; then
    pass "unmeshed direct call (plaintext): no answer from the resource; its sidecar's inbound listener counted the refused connection (no_filter_chain_match ${nb:-?} -> ${na:-?}; diff in unmeshed-stats-diff.txt)"
  else
    fail "unmeshed direct call: $(head -c 200 "$out/unmeshed-response.txt" | tr '\r\n' '  '); receiver counters unchanged"
  fi
fi
k logs "$resource_pod" -c ztd-protected-resource --since-time="$probes_from" > "$out/resource-app-log-during-probes.txt" 2>/dev/null || true
if [ ! -s "$out/resource-app-log-during-probes.txt" ]; then
  pass "the resource application logged nothing while the probes called it: no direct request reached it"
else
  fail "the resource application logged $(wc -l < "$out/resource-app-log-during-probes.txt") line(s) during the probes"
fi

echo "== 3. The namespace as found"
cleanup; trap - EXIT
snapshot "$out/after"
if diff "$out/before/objects.json" "$out/after/objects.json" > "$out/objects.diff" && diff "$out/before/releases.json" "$out/after/releases.json" >> "$out/objects.diff"; then
  pass "no policy, workload, Service or release of $ns changed (resourceVersions equal)"
else
  fail "the namespace changed: see objects.diff"
fi
echo "finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$out/run.txt"
echo "verdict: $([ "$failures" = 0 ] && echo PASS || echo "FAIL ($failures)")" | tee -a "$out/verdict.txt"
exit "$failures"
