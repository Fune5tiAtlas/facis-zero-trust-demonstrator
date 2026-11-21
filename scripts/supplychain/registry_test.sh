#!/usr/bin/env bash
# Cases for registry.sh: GHCR by default, lower-cased; Harbor once HARBOR_HOST and HARBOR_PROJECT are
# set; a host with a scheme, or a host without a project, is refused.
#
#   scripts/supplychain/registry_test.sh
set -euo pipefail
script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/registry.sh"
failures=0
want() { # name expected env...
  local name=$1 expected=$2 got; shift 2
  if got="$(env -i PATH="$PATH" "$@" "$script" 2>/dev/null)" && [ "$got" = "$expected" ]; then echo "ok    $name"
  else echo "FAIL  $name (got '${got:-<refused>}')"; failures=$((failures + 1)); fi
}
refused() { # name env...
  local name=$1; shift
  if env -i PATH="$PATH" "$@" "$script" >/dev/null 2>&1; then echo "FAIL  $name (accepted)"; failures=$((failures + 1))
  else echo "ok    $name"; fi
}
want "GHCR by default, lower case" $'kind=ghcr\nhost=ghcr.io\npath=ghcr.io/owner/repo' GITHUB_REPOSITORY=Owner/Repo
want "Harbor when host and project are set" $'kind=harbor\nhost=harbor.example.org\npath=harbor.example.org/facis-ztd' \
  GITHUB_REPOSITORY=Owner/Repo HARBOR_HOST=harbor.example.org HARBOR_PROJECT=facis-ztd
refused "a host with a scheme is refused" HARBOR_HOST=https://harbor.example.org HARBOR_PROJECT=p
refused "a host without a project is refused" HARBOR_HOST=harbor.example.org
[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
