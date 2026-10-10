#!/usr/bin/env bash
# Remove the two local zones and the files zones-up.sh wrote.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="$root/.dev/zones"

# Fails here, keeping the files, if the clusters cannot be listed (for example Docker is down).
clusters="$(kind get clusters)"
for zone in zone-a zone-b; do
  if grep -qx "ztd-$zone" <<<"$clusters"; then
    KUBECONFIG="$out/kubeconfig-$zone" kind delete cluster --name "ztd-$zone"
  fi
done
rm -rf "$out"
