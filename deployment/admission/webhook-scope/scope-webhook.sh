#!/usr/bin/env bash
# Helm post-renderer for the Gatekeeper chart: restricts the validation webhook to namespaces labelled
# facis.ztd/admission-proof=true. The chart's namespaceSelector values can only exclude namespaces;
# this adds the positive selector to the rendered webhook, next to the chart's own expressions. It
# fails if the webhook's selector is not where the chart puts it, so a chart change cannot silently
# widen the scope.
set -euo pipefail
awk '
  /name: validation\.gatekeeper\.sh$/ { webhook = 1 }
  { print }
  webhook && /- key: admission\.gatekeeper\.sh\/ignore$/ { match($0, /^ */); indent = substr($0, 1, RLENGTH) }
  webhook && indent != "" && /operator: DoesNotExist$/ {
    print indent "- key: facis.ztd/admission-proof"
    print indent "  operator: In"
    print indent "  values:"
    print indent "  - \"true\""
    webhook = 0; indent = ""; done = 1
  }
  END {
    if (!done) { print "ztd-webhook-scope: the validation webhook namespaceSelector was not found" > "/dev/stderr"; exit 1 }
  }
'
