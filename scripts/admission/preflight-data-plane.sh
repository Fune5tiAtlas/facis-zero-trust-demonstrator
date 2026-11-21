#!/usr/bin/env bash
# Read-only preflight before a namespace is put under admission control (the umbrella's
# admission.enforceDataPlane labels the data-plane namespace facis.ztd/admission-proof=true). Lists
# every image of the namespace's Pods and of the pod templates of its Deployments, ReplicaSets,
# StatefulSets, DaemonSets, Jobs and CronJobs - containers, init containers and ephemeral containers -
# and classifies each one as the image policy would see it:
#
#   trusted-repository  a digest reference from an allowed repository: admitted if the provider then
#                       verifies its signature and attestations (not checked here)
#   allow-listed        an exact allowedDigests reference: admitted without further checks
#   DENIED <code>       ADM-NOT-DIGEST (tag, no registry host) or ADM-REGISTRY-DENIED
#
#   scripts/admission/preflight-data-plane.sh <namespace>
#
# The allowed repositories and the allow-list are read from the provider's trust policy (ConfigMap
# ztd-admission-provider-trust in TRUST_NAMESPACE, default gatekeeper-system), or given as
# REPOSITORIES and ALLOWED_DIGESTS (space-separated; both set, the cluster's policy is not read).
# kubectl get only. Exits 1 if any image would be denied, 2 on a usage or read error.
set -euo pipefail

ns=${1:?usage: preflight-data-plane.sh <namespace>}
if [ -n "${REPOSITORIES:-}" ] && [ -n "${ALLOWED_DIGESTS+set}" ]; then
  repos=$REPOSITORIES allowed=$ALLOWED_DIGESTS
else
  policy=$(kubectl -n "${TRUST_NAMESPACE:-gatekeeper-system}" get configmap ztd-admission-provider-trust -o jsonpath='{.data.policy\.json}') ||
    { echo "cannot read the provider trust policy; set REPOSITORIES and ALLOWED_DIGESTS" >&2; exit 2; }
  repos=${REPOSITORIES:-$(jq -r '.repositories[]?' <<<"$policy")}
  allowed=${ALLOWED_DIGESTS-$(jq -r '.allowedDigests[]?' <<<"$policy")}
fi
[ -n "$repos" ] || { echo "no allowed repository" >&2; exit 2; }

# image <TAB> kind/name/container, one line per container of every pod spec in the namespace.
uses=$(kubectl -n "$ns" get pods,deployments,replicasets,statefulsets,daemonsets,jobs,cronjobs -o json | jq -r '
  .items[] | . as $o
  | (if .kind == "Pod" then .spec elif .kind == "CronJob" then .spec.jobTemplate.spec.template.spec else .spec.template.spec end) as $s
  | ("containers", "initContainers", "ephemeralContainers") as $f
  | ($s[$f] // [])[] | [.image, "\($o.kind)/\($o.metadata.name)/\(.name)"] | @tsv') ||
  { echo "cannot list the workloads of namespace $ns" >&2; exit 2; }

# The same digest reference rule as the ztd-image-digest constraint.
digest_ref='^(localhost(:[0-9]+)?|[a-z0-9-]+(\.[a-z0-9-]+)+(:[0-9]+)?|[a-z0-9-]+:[0-9]+)/[a-z0-9]+([._-]+[a-z0-9]+)*(/[a-z0-9]+([._-]+[a-z0-9]+)*)*@sha256:[a-f0-9]{64}$'
classify() { # image
  local r
  [[ "$1" =~ $digest_ref ]] || { echo "DENIED ADM-NOT-DIGEST"; return; }
  for r in $allowed; do [ "$1" = "$r" ] && { echo allow-listed; return; }; done
  for r in $repos; do
    r=${r%/}
    case "${1%@*}" in "$r" | "$r"/*) echo trusted-repository; return ;; esac
  done
  echo "DENIED ADM-REGISTRY-DENIED"
}

denied=0 total=0
while IFS=$'\t' read -r image where; do
  [ -n "$image" ] || continue
  class=$(classify "$image")
  total=$((total + 1))
  case "$class" in DENIED*) denied=$((denied + 1)) ;; esac
  printf '%-30s %s  (%s)\n' "$class" "$image" "$where"
done < <(sort -u <<<"$uses")
echo "$total image use(s) in $ns, $denied would be denied"
[ "$denied" -eq 0 ]
