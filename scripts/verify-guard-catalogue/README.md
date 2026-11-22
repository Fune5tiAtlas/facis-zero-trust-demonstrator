# verify-guard-catalogue

The guard's negative-case catalogue (FZTD-107) through the deployed chain on a throwaway kind
cluster: the guard chart (Envoy with the ext_authz hook, the policy evaluator) installed from values
only, the protected resource, the token store and the connector from the working tree, PostgreSQL
and OpenBao from the pinned images, every pod meshed by Istio 1.31.1 with STRICT mTLS and the zone's
XFCC sanitization (`zone-policy`, EnvoyFilter `xfcc-sanitize-set`).

```sh
scripts/verify-guard-catalogue/verify.sh [--out DIR]     # default .dev/guard-catalogue (git-ignored)
```

Needs docker, go, helm, kind, kubectl, curl, jq and openssl. `KEEP=1` leaves the cluster running.

## What it proves

| Case | Caller's answer | Decision events (IF-01 v2) |
|---|---|---|
| allowed (control) | 200 from the resource | guard `allowed`, policy rule `m3-report-summary`; the same id in the resource's record and on the feed bridge |
| no token | 401 `TOK-MISSING` | guard, bundle and rule `not_evaluated` |
| missing proof | 401 `TOK-PROOF-INVALID` | guard, detail `proof_absent` |
| proof signed by the wrong key | 401 `TOK-JKT-MISMATCH` | guard |
| insufficient scope | 403 `POL-RULE-DENY`, rule `m3-scope-required` | guard and policy |
| policy-only denial | 403 `POL-RULE-DENY`, rule `m3-client-blocked` | guard and policy |
| presentation required | 401 `POL-PRESENTATION-REQUIRED`, the OID4VP link in the body | guard and policy |
| replayed proof | 401 `TOK-REPLAY` | guard |
| wrong mesh caller | 403 `RBAC: access denied` from the guard's sidecar | none: refused before the hook |
| policy engine down | 503 `POL-PDP-UNAVAILABLE` | guard |
| token store down | 503 `TOK-STORE-UNAVAILABLE` | guard |
| expired token | 401 `TOK-EXPIRED` | guard |

A token for the wrong audience cannot be obtained by a participant at all (the connector refuses it
the challenge); `TestGuardWithRealConnectorStorePolicyPostgresAndOpenBao` covers that case and the
guard's own `MESH-PAIR-DENIED` on the token path with the real connector, store, PostgreSQL and
OpenBao, and writes the same catalogue to `$GUARD_CATALOGUE_OUT/catalogue.json`.

The feed bridge is then installed from its chart (`deployment/helm/feed-bridge`) in the mesh: the
producer identity posts the guard's and the policy's lines to `/ingest`, the UI's identity reads
both feed versions and finds the allowed request's events, and the Participant's identity (feed) and
another identity (`/ingest`) are refused by the bridge's sidecar (`403 RBAC: access denied`).

The run also records the latency of the presentation-required decision through the guard (the
whole chain, denied at policy, 401) against a mesh round trip from the same pod to another service
without the guard (the connector's key set, 200), `GUARD_CATALOGUE_SAMPLES` (100) of each,
sequential, measured by curl inside the participant's pod.

## Not proven here

The mesh is Istio's own CA with trust domain `cluster.local`, not the zone's SPIRE chain
(`scripts/verify-mesh-identity`); no admission policy runs; the cluster's CNI is kind's. The live
proofs on the zones are archived under `docs/evidences/`.

## The record

`verdict.txt`, `catalogue.tsv` (one row per case: status, reason code, rule, correlation id, the
guard's and the policy's event, the verdict), each response (`<case>.http`), the guard's and the
policy's event lines, the resource's record of the allowed request, the feed bridge's snapshot and
stream per run, `latency.tsv` and `environment.json`. Exit status: the number of failed checks.
