#!/usr/bin/env bash
# Cases for env-audit.sh's decision: a probe job refused by the environment before any step ran is
# "refused"; one that ran a step is "admitted"; anything else - waiting for a reviewer, failed for
# another reason, never found - is "inconclusive". And an allowlisted ref cannot be the probe.
#
#   scripts/supplychain/env-audit_test.sh
set -euo pipefail
# shellcheck source=scripts/supplychain/env-audit.sh disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env-audit.sh"
failures=0
want() { # name expected job notes
  local got; got="$(verdict "$3" "$4")"
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1 (got $got, want $2)"; failures=$((failures + 1)); fi
}
refusal='Branch "audit/env-probe-1" is not allowed to deploy to release due to environment protection rules.'
want "refused before any step" refused '{"status":"completed","conclusion":"failure","steps":[]}' "$refusal"
want "a step ran: admitted" admitted \
  '{"status":"completed","conclusion":"success","steps":[{"name":"Set up job","conclusion":"success"}]}' ""
want "failed without the environment's refusal: inconclusive" inconclusive '{"status":"completed","conclusion":"failure","steps":[]}' "runner lost"
want "waiting for a reviewer: inconclusive" inconclusive '{"status":"waiting","conclusion":null,"steps":[]}' ""
want "no probe job found: inconclusive" inconclusive '{}' ""
for ref in main candidate/x v1.2.3; do
  if allowlisted "$ref"; then echo "ok    $ref is allowlisted, so not a probe"; else echo "FAIL  $ref"; failures=$((failures + 1)); fi
done
if allowlisted audit/env-probe-1; then echo "FAIL  the disposable branch is allowlisted"; failures=$((failures + 1)); else echo "ok    the disposable branch is outside the allowlist"; fi
[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
