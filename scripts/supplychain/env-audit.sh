#!/usr/bin/env bash
# The audit of the release environment's allowlist (FZTD-57): a run from a ref the environment must not
# admit is started, and its probe job - which names the release environment and holds no secret - must
# have been refused by the environment before any step ran. Run by the Environment audit job of
# signing-environment-audit.yml, by hand only.
#
#   1. the probe ref: PROBE_REF if given, else a disposable branch audit/env-probe-<run id> created at
#      this commit (and deleted at the end); a ref the allowlist admits is refused as a probe;
#   2. signing-environment-audit.yml dispatched on it with mode=probe, the run found and waited for;
#   3. the verdict from the probe job and its annotations: refused (no step ran, the job failed and
#      GitHub says the ref is not allowed to deploy), admitted (a step ran), or inconclusive.
#
# Writes <out>/env-audit.json and exits 0 only for "refused".
#
#   GH_TOKEN=... GITHUB_REPOSITORY=... GITHUB_RUN_ID=... GITHUB_SHA=... [PROBE_REF=...] \
#     scripts/supplychain/env-audit.sh <out dir>
#
# The decision is a function, sourced by env-audit_test.sh.
set -euo pipefail

WORKFLOW=signing-environment-audit.yml
PROBE_JOB="Environment probe"

# verdict <probe job JSON> <annotation messages>  -> refused|admitted|inconclusive
verdict() {
  local job=$1 notes=$2
  if [ "$(jq -r '[.steps[]? | select(.conclusion != null and .conclusion != "skipped")] | length' <<<"$job")" != 0 ]; then
    echo admitted
  elif [ "$(jq -r '.status + "/" + (.conclusion // "")' <<<"$job")" = completed/failure ] \
    && grep -qiE 'not allowed to deploy to release|environment protection rules' <<<"$notes"; then
    echo refused
  else
    echo inconclusive
  fi
}

# allowlisted <ref>  -> succeeds for a ref the release environment is meant to admit
allowlisted() { case "$1" in main|candidate/*|v*) return 0 ;; *) return 1 ;; esac; }

main() {
  [ $# -eq 1 ] || { echo "usage: $0 <out dir>" >&2; exit 2; }
  local out=$1 repo=$GITHUB_REPOSITORY ref=${PROBE_REF:-} since run="" job="{}" notes="" result
  mkdir -p "$out"
  if [ -z "$ref" ]; then
    ref="audit/env-probe-$GITHUB_RUN_ID"
    gh api -X POST "repos/$repo/git/refs" -f ref="refs/heads/$ref" -f sha="$GITHUB_SHA" >/dev/null
    # shellcheck disable=SC2064 # the ref is fixed now
    trap "gh api -X DELETE 'repos/$repo/git/refs/heads/$ref' >/dev/null 2>&1 || true" EXIT
  fi
  if allowlisted "$ref"; then
    echo "::error::$ref is on the release environment's allowlist; the probe needs a ref outside it" >&2
    exit 1
  fi

  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  gh workflow run "$WORKFLOW" --repo "$repo" --ref "$ref" -f mode=probe
  for _ in $(seq 60); do
    sleep 10
    run="$(gh api -X GET "repos/$repo/actions/workflows/$WORKFLOW/runs" -f branch="$ref" -f event=workflow_dispatch \
      -f created=">=$since" --jq '.workflow_runs[0] | select(.status == "completed") | .id')"
    [ -z "$run" ] || break
  done
  if [ -n "$run" ]; then
    job="$(gh api "repos/$repo/actions/runs/$run/jobs" --jq "[.jobs[] | select(.name == \"$PROBE_JOB\")][0] // {}")"
    if [ "$(jq -r '.id // empty' <<<"$job")" != "" ]; then
      notes="$(gh api "repos/$repo/check-runs/$(jq -r .id <<<"$job")/annotations" --jq '.[].message' 2>/dev/null || true)"
    fi
  fi
  result="$(verdict "$job" "$notes")"
  jq -n --arg ref "$ref" --arg run "$run" --arg result "$result" --argjson job "$job" \
    --arg allowed "main, candidate/*, v*" \
    '{probeRef: $ref, probeRun: (if $run == "" then null else ($run | tonumber) end), allowlist: $allowed,
      probeJob: {conclusion: $job.conclusion, stepsRun: ([$job.steps[]? | select(.conclusion != null and .conclusion != "skipped")] | length)},
      result: $result}' > "$out/env-audit.json"
  echo "environment audit: probe from $ref, run ${run:-none}: $result"
  [ "$result" = refused ]
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
