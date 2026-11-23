# Mesh rows as executable BDD scenarios: runs of 23 Nov 2026

The Annex A rows of the family *Mesh enrolment and segmentation* that an existing proof can decide on
the participant zones now run as `@cluster` scenarios (`features/go/mesh.feature`), with their steps in
`internal/bdd/mesh_cluster_test.go` and the decision rules held offline by `internal/bdd/mesh_decide_test.go`.
The rows are about the participant zone clusters A and B (Istio sidecar mode with SPIRE, Cilium). The IONOS
cluster runs ambient mesh without SPIRE under its own declared deviation and is not a target of these
scenarios.

| Row | Mode | Proof the steps run | Decided from |
|---|---|---|---|
| ZT-23 Service Mesh Implementation | cluster | `scripts/verify-plane-separation/verify.sh` | `matrix.csv`: every legitimate caller served over mTLS and counted by its proxy to the destination's SPIFFE ID; every plain-text request without an identity let through by the network (Hubble `FORWARDED`) and reset by the destination's proxy under mTLS `STRICT`; the verifier's run with no failed check |
| ZT-25 Routing Policies | cluster | the same run, plus `scripts/ci/check-policy-addresses.sh` | the legitimate callers (as above), every impostor refused `403 RBAC` with a denial line naming both SPIFFE IDs, every unlabelled caller and every proxy-less probe dropped by the network policy (Hubble policy drop cited); no address in a policy, in the zone file's render and in the live NetworkPolicies, CiliumNetworkPolicies, CiliumClusterwideNetworkPolicies and AuthorizationPolicies of the plane namespaces and cluster-wide (the Connector's two declared edge hops reported `EDGE`) |
| ZT-61 Traffic routed via Service Mesh | cluster | the same run | legitimate callers counted over mTLS; impostors refused by the mesh; unlabelled callers dropped by the network |
| ZT-62 Limited Communication within Mesh | cluster | the same run | the ALLOW rows that have an impostor (the export row admits every identity and has none): the permitted identity served over mTLS, the other refused by mesh policy with both identities logged |
| ZT-26 Ingress and Egress | cluster | `scripts/verify-connector-routing/verify.sh`, `ROLE=egress` on zone A, `ROLE=ingress` on zone B | the record: the role's section, the direct paths (each drop cited from Hubble) and both exemptions (DNS, observability export) present, no failed check, `Result: 0 failed check(s).` |

The four rows on the plane-separation verifier share one run per target and run id within a test process.
Each row writes `bundles/bdd/evidence/bdd-zt-0xx/<target>/<run>/decision.txt`; the verifier's record is in
`bundles/bdd/evidence/bdd-mesh/<target>/<run>/plane-separation/`, the routing record in
`bundles/bdd/evidence/bdd-zt-026/<target>/<run>/connector-routing/` (all git-ignored). In the cluster dry run
every step is skipped.

## The runs

Commit `b9f0bb8b`, `BDD_MODE=cluster`, `-godog.tags=@ZT-23,@ZT-25,@ZT-26,@ZT-61,@ZT-62`, the zone file of
the zone (`deployment/helm/ztd/zones/zone-<a|b>.yaml`). The Connector routing inputs are those of the
21 Nov records ([connector-routing](../connector-routing/README.md)): zone A `POST /demo` with the peer log
read from zone B's entry; zone B the entry `ztd-m3-b/ztd-edge`, `declared/zone-b.txt`,
`TSPA_FRAMEWORK=trust.facis.cloud`, the five direct targets of `ztd-m3-b` and one external address on 443.

| Target | kube-system UID | BDD run id | Plane-separation run | Routing run |
|---|---|---|---|---|
| `zerotrust-a` | `3fbf9fda-5cd2-459a-87f0-769126697d9a` | `mesh-a-20261123-r2` (13:26-13:59Z) | `rfcec4809`: 101 pass, 8 fail, 11 n/a, 3 declared | `20261123T135615Z-90119`: 0 failed |
| `zerotrust-b` | `a39ae8ea-ac02-4aec-9c13-cda127b17e2d` | `mesh-b-20261123-r2` (13:12-13:28Z) | `rcb2d7bdb`: 31 pass, 8 fail, 5 n/a, 1 declared | `20261123T132407Z-86899`: 2 failed |

| Row | zone A | zone B |
|---|---|---|
| ZT-23 | failed | failed |
| ZT-25 | failed | failed |
| ZT-61 | failed | failed |
| ZT-62 | failed | failed |
| ZT-26 | **passed** | failed |

### Why the rows fail

- **The zones run an older allow matrix than the zone files of this commit.** On both zones the same 8 lines
  fail: the legitimate caller and the impostor of `pdp-adapter-to-tsa`, `token-store-to-verification-service`,
  `connector-to-openbao` and `token-store-to-openbao` are dropped at the network (`denied(28)`). The zone files
  render the `pdp-adapter-to-tsa` pair on the label `app.kubernetes.io/name=ztd-policy-evaluator`; the live pair
  still selects `pdp-adapter`. The three other rows have no NetworkPolicy pair on the zones. Every other lane
  holds: the other ALLOW rows' legitimate callers served over mTLS, their impostors refused `403 RBAC` with both SPIFFE IDs,
  their unlabelled callers dropped with Hubble's policy drop, every proxy-less probe dropped, every plain-text
  request reset under `STRICT` (13 on zone A, 2 on zone B). The rows pass only after the umbrella release of each
  zone is upgraded to this zone file, which this work does not do.
- **ZT-26 on zone B**: the trust list of `trust.facis.cloud` and its VC answer 404 through `tspa-public`, as on
  21 Nov. Every other check of the ingress role passed (25 entry checks, the 6 direct paths dropped with Hubble's
  drop, DNS and the export lane).
- **No address in any mesh policy** held on both zones (zone A 60 live policies, zone B 71; the render of each
  zone file) and is part of ZT-25's decision, which fails only on the lanes above.

Two earlier runs the same day (`mesh-a-20261123`, `mesh-b-20261123`, commit `e0a7a21d`) are void: the
worktree had no built chart dependencies, so the umbrella did not render, and the routing record was not
found (the proof does not take `ZTD_EVIDENCE_DIR` on a host without GNU `realpath`; the scenario now reads the
run directory the proof prints and copies the record in).

## Rows left pending

- **ZT-01 Secure Service Mesh**: needs "a workload outside the mesh attempts the same call" as an in-mesh pair.
  No proof that runs on the zones without reinstalling them makes a proxy-less workload attempt an ALLOW lane's
  call: the plane-separation verifier sends proxy-less probes only to DENY and catch-all destinations, and
  `verify-mesh-identity`'s `unregistered-workload-cut-off` reinstalls the zone. The guard bypass record shows
  an unmeshed pod cannot be created at all, which is a different refusal.
- **ZT-27 Observability**: no OpenTelemetry Collector, Prometheus or tracing backend runs on zone A or B; the
  observability proof (`scripts/verify-observability/verify.sh`) stops and restores the zone's SPIRE server,
  an agent, a node collector and the zone gateway; and no proof asserts "a component emitting no telemetry is
  visible as a gap in the correlated trace".
- **ZT-58 Service Mesh Setup**: the per-node proof (`mesh-on-every-node`, `cross-node-calls`) is
  `scripts/verify-mesh-identity/verify.sh`, which uninstalls and reinstalls the zone on every run; it can only
  run on kind or under an approved reinstall of a participant zone (`ZTD_KEEP_ZONE`).

## Limits

- The destinations of most ALLOW rows are the verifier's stand-ins, not the real services.
- Trust domains are the interim `zone-*.trust.invalid` names.
- The plane-separation verifier lifts the capture validation of `proxy-takes-spire-socket` for under a minute
  per run, as documented in its README; both zones were checked after the runs: no probe object remains.
