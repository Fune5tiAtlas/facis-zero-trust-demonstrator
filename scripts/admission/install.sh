#!/usr/bin/env bash
# Install admission control on the current kube context, in the reviewed order: Gatekeeper (pinned
# chart, gatekeeper-values.yaml, the webhook-scope post-renderer, every image pinned by digest), the
# image-verification provider, the constraint templates, the exemptions, the constraints, then the
# admission pool (namespaces and tester identity). Re-running it upgrades in place. It stops at the
# first check that fails: an unpinned image, a webhook not scoped to the admission label, a Gatekeeper
# response cache that is on, or a constraint not enforced.
#
#   BIN=<dir holding the Gatekeeper chart archive> PROVIDER_IMAGE=<repository@sha256:...> \
#   TRUST_REPOSITORY=<host/path> TRUST_KEY=<cosign public key file> \
#   [GATEKEEPER_REPLICAS=2] [PROVIDER_REPLICAS=2] [PLAIN_HTTP_REGISTRY=host:port] \
#   [ALLOWED_DIGESTS="host/repository@sha256:<digest> ..."] scripts/admission/install.sh
#
# ALLOWED_DIGESTS (space-separated, default none) are third-party images admitted by exact digest
# reference, such as the injected Istio proxy; the one list goes to both the provider's
# trust.allowedDigests and the ztd-allowed-repositories constraint's allowedDigests.
#
# The standalone layout. A zone whose zone file sets admission.install has the umbrella layout
# instead - one release gatekeeper of deployment/helm/ztd, installed by scripts/install-zone/install.sh -
# and this script refuses it, except as the rollback to this layout (docs/umbrella-chart.md, "Admission
# in the umbrella"): FROM_UMBRELLA=1 drops the umbrella release's records, leaving every object in
# place, and adopts the objects into the three releases here (helm --take-ownership).
#
# Break-glass: delete the ValidatingWebhookConfiguration gatekeeper-validating-webhook-configuration,
# then helm uninstall gatekeeper -n gatekeeper-system.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
# shellcheck source=scripts/admission/checks.sh
. scripts/admission/checks.sh
: "${BIN:?set BIN}" "${PROVIDER_IMAGE:?set PROVIDER_IMAGE}" "${TRUST_REPOSITORY:?set TRUST_REPOSITORY}" "${TRUST_KEY:?set TRUST_KEY}"
chart="$BIN/gatekeeper-$GATEKEEPER_CHART_VERSION.tgz"
case "$PROVIDER_IMAGE" in *@sha256:*) ;; *) echo "PROVIDER_IMAGE must be a digest reference" >&2; exit 2 ;; esac
allowed_digests=()
for d in ${ALLOWED_DIGESTS:-}; do
  [[ "$d" =~ ^[a-z0-9.:-]+/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]] || { echo "ALLOWED_DIGESTS entry '$d' is not host/repository@sha256:<digest>" >&2; exit 2; }
  allowed_digests+=("$d")
done
allowed_json=$(printf '%s\n' ${allowed_digests[@]+"${allowed_digests[@]}"} | jq -Rsc 'split("\n") | map(select(. != ""))')

# The rollback is resumable: with FROM_UMBRELLA=1 every release here adopts (--take-ownership) on
# every run, so a run interrupted after Gatekeeper but before the provider or the pool is re-run as
# it is; the umbrella's records are dropped only while release gatekeeper is still the umbrella's,
# and only once the inputs are checked.
adopt=()
if [ "${FROM_UMBRELLA:-}" = 1 ]; then
  [ -f "$chart" ] || { echo "Gatekeeper chart not found: $chart" >&2; exit 2; }
  grep -qs "BEGIN PUBLIC KEY" "$TRUST_KEY" || { echo "TRUST_KEY is not a PEM public key file: $TRUST_KEY" >&2; exit 2; }
  adopt=(--take-ownership)
  if [ "$(admission_layout)" = umbrella ]; then
    echo "== Rollback from the umbrella layout: dropping release gatekeeper's records, keeping its objects"
    admission_forget gatekeeper
  fi
elif [ "$(admission_layout)" = umbrella ]; then
  echo "the admission stack is release gatekeeper of the umbrella chart (scripts/install-zone/install.sh); FROM_UMBRELLA=1 rolls it back to this layout" >&2
  exit 1
fi

# The webhook-scope post-renderer is a Helm plugin; it lives in this run's own Helm directory.
helm_home="$(mktemp -d)"
trap 'rm -rf "$helm_home"' EXIT
admission_helm_home "$helm_home"

echo "== Gatekeeper"
gatekeeper_values=(-f deployment/admission/gatekeeper-values.yaml --set replicas="${GATEKEEPER_REPLICAS:-2}"
  --set image.release="${GATEKEEPER_IMAGE#*:}"
  --set preInstall.crdRepository.image.repository="${GATEKEEPER_CRDS_IMAGE%%:*}"
  --set preInstall.crdRepository.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}"
  --set postInstall.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}"
  --set postUpgrade.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}"
  --set postInstall.probeWebhook.enabled=false --post-renderer ztd-webhook-scope)
unpinned=$(helm template gatekeeper "$chart" -n gatekeeper-system "${gatekeeper_values[@]}" | grep -E '^\s*image:' | grep -v '@sha256:' || true)
[ -z "$unpinned" ] || { echo "Gatekeeper images not pinned by digest:" >&2; echo "$unpinned" >&2; exit 1; }
helm upgrade --install gatekeeper "$chart" -n gatekeeper-system --create-namespace "${gatekeeper_values[@]}" ${adopt[@]+"${adopt[@]}"} --wait --timeout 8m >/dev/null
# Both webhooks must select only the admission namespaces.
unscoped=$(admission_unscoped)
[ -z "$unscoped" ] || { echo "webhooks not scoped to facis.ztd/admission-proof=true: $unscoped" >&2; exit 1; }
ttl=$(admission_cache_ttl)
[ "$ttl" = "response-cache-ttl=0s" ] || { echo "Gatekeeper response cache is not off: '$ttl'" >&2; exit 1; }
echo "webhooks scoped to facis.ztd/admission-proof=true; $ttl"

echo "== Provider"
provider_values=(--set replicas="${PROVIDER_REPLICAS:-2}" --set image.repository="${PROVIDER_IMAGE%@*}" --set image.digest="${PROVIDER_IMAGE#*@}"
  --set-json "trust.repositories=[\"$TRUST_REPOSITORY\"]" --set-file trust.publicKeys="$TRUST_KEY")
[ -z "${PLAIN_HTTP_REGISTRY:-}" ] || provider_values+=(--set insecurePlainHTTPRegistry="$PLAIN_HTTP_REGISTRY")
[ ${#allowed_digests[@]} -eq 0 ] || provider_values+=(--set-json "trust.allowedDigests=$allowed_json")
helm upgrade --install admission deployment/helm/admission -n gatekeeper-system "${provider_values[@]}" ${adopt[@]+"${adopt[@]}"} --wait --timeout 5m >/dev/null

echo "== Policy"
kubectl apply -f deployment/admission/templates/ >/dev/null
for kind in k8sztdimagedigest k8sztdallowedrepositories k8sztdnaming k8sztdverifiedimages; do
  for _ in $(seq 60); do kubectl get crd "$kind.constraints.gatekeeper.sh" >/dev/null 2>&1 && break; sleep 2; done
  kubectl wait --for=condition=established --timeout=120s "crd/$kind.constraints.gatekeeper.sh" >/dev/null
done
kubectl apply -f deployment/admission/exemptions.yaml >/dev/null
sed -e "s|ghcr.io/eclipse-xfsc/facis-zero-trust-demonstrator|$TRUST_REPOSITORY|" -e "s|^    allowedDigests: \[\]$|    allowedDigests: $allowed_json|" \
  deployment/admission/constraints/allowed-repositories.yaml | kubectl apply -f - >/dev/null
for c in image-digest naming verified-images; do kubectl apply -f "deployment/admission/constraints/$c.yaml" >/dev/null; done
# Each constraint must be acknowledged, current and error-free, by every Ready webhook replica.
admission_wait_enforced
echo "constraints enforced by every webhook replica"

echo "== Admission pool"
helm upgrade --install admission-pool deployment/helm/admission-pool -n gatekeeper-system ${adopt[@]+"${adopt[@]}"} --wait >/dev/null
kubectl get namespaces -l facis.ztd/admission-proof=true -o name
