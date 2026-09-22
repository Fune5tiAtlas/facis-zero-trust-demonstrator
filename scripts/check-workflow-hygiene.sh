#!/usr/bin/env bash
#
# Fails when a workflow references an unpinned action, omits its permissions block, or
# grants a wildcard write scope. Usage: scripts/check-workflow-hygiene.sh [directory]

set -euo pipefail

dir="${1:-.github/workflows}"
status=0

fail() {
  printf 'FAIL  %s\n' "$1" >&2
  status=1
}

shopt -s nullglob
files=("$dir"/*.yml "$dir"/*.yaml)
if [ ${#files[@]} -eq 0 ]; then
  echo "No workflows found in $dir" >&2
  exit 1
fi

for file in "${files[@]}"; do
  while read -r ref; do
    # Local actions and the shared eclipse-xfsc workflows are exempt - see docs/ci-cd.md.
    case "$ref" in
      ./*|eclipse-xfsc/*) continue ;;
    esac
    if [[ ! "${ref##*@}" =~ ^[0-9a-f]{40}$ ]]; then
      fail "$file: action '$ref' is not pinned to a commit SHA"
    fi
  done < <(grep -oE '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*[^[:space:]#]+' "$file" |
    sed -E 's/.*uses:[[:space:]]*//')

  # Without a top-level block the workflow inherits the repository default token scope.
  if ! grep -qE '^permissions:' "$file"; then
    fail "$file: no top-level permissions block"
  fi

  if grep -qE '\bwrite-all\b' "$file"; then
    fail "$file: wildcard write scope (write-all)"
  fi
done

if [ $status -eq 0 ]; then
  echo "OK    ${#files[@]} workflow(s) pinned and scoped"
fi

exit $status
