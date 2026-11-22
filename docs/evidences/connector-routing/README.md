# Zero Trust Connector routing (ZT-26): evidence of 21 Nov 2026

The records of the runs behind [Zero Trust Connector routing](../../architecture.md#zero-trust-connector-routing-zt-26),
copied from the run directories with every address masked (the proofs' own masking; local paths replaced).
The proof is `scripts/verify-connector-routing/verify.sh`; the kind rehearsal `kind.sh` beside it.

| Record | Where | Commit | Result |
|---|---|---|---|
| [kind-2026-11-21.md](kind-2026-11-21.md) | kind: a peer entry outside the cluster; the egress role routed to it; zone B's hand-applied entry adopted by the ingress role; the caller's service account created beforehand | `5183320a` | rehearsal 8/8, ROLE=egress 12/12, ROLE=ingress 8/8 PASS; a pod with the gateway's label under another identity dropped; the pre-existing account left in place; the adoption lost 1 of 35 calls (the hand-applied pod has no preStop pause), a later rollout none of 37 |
| [zone-b-entry-adoption-2026-11-21.md](zone-b-entry-adoption-2026-11-21.md) | `zerotrust-b`: the entry `ztd-edge` adopted by release `ztd-edge` | `895531dc` | guarded path PASS before and after; Service UID, node port and address unchanged; 42 of 42 outside calls served |
| [reapply-2026-11-21.md](reapply-2026-11-21.md) | both zones: the corrected chart (identity-bound egress lane, one policy per hop) | `5183320a` | no pod rolled; zone B guarded path PASS before, between and after (one admission retry) |
| [zone-a-2026-11-21.md](zone-a-2026-11-21.md) | `zerotrust-a`, ROLE=egress | `5183320a` | 12/12 PASS: guarded `POST /demo` from zone A served through both Connector components and logged by each; the gateway's label on another identity, and the direct attempt, dropped by policy (Hubble) and absent from the entry's log; impostor refused (403, denial line); DNS; export lane |
| [zone-b-2026-11-21.md](zone-b-2026-11-21.md) | `zerotrust-b`, ROLE=ingress | `28896c0e` | 22/22 PASS: every direct target dropped by policy (Hubble); the only exposed Services are the entry and the two declared TRAIN listeners, each held to its scope from outside (TSPA entry: DID document served, writes and the actuator 404, TLS 1.2 refused; DNS listener: its zone answered, other names refused); DNS; export lane |
| [network-check-2026-11-21.md](network-check-2026-11-21.md) | both zones: `ztd-network-check` | n/a | egress narrowed to its own pods on 8080; outside 443 now refused, peer 8080 still served |
| [plane-separation-zone-a-2026-11-21.md](plane-separation-zone-a-2026-11-21.md) | `zerotrust-a` with the first gateway revision | `bb6f42c6` | 71 pass, 0 fail, 5 n/a, 1 declared |
| [plane-separation-kind-2026-11-21.md](plane-separation-kind-2026-11-21.md) | kind with the first gateway revision | `895531dc` | 67 pass, 0 fail, 6 n/a, 1 declared |

Live state left in place: zone A `ztd-data` runs release `ztd-connector-gateway` (its peer, zone B's entry
address and CA, given at install, not committed); zone B `ztd-m3-b` runs release `ztd-edge`. Rollback, in
fail-closed order: zone A, scale the gateway to 0 (routing stops), then uninstall the release (its policies
go; the namespace default deny stays); zone B, as in the adoption record.

Not shown here: the observability export to a real collector (no collector runs on the zones; the export
lane is proven with a stand-in carrying the row's labels and identity); the inter-zone transport is TLS over
public transit, not the attested channel ([Specifications](../../specifications.md)).
