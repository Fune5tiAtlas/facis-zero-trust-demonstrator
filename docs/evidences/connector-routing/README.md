# Zero Trust Connector routing (ZT-26): evidence of 21 Nov 2026

The records of the runs behind [Zero Trust Connector routing](../../architecture.md#zero-trust-connector-routing-zt-26),
copied from the run directories with every address masked (the proofs' own masking; local paths replaced).
The proof is `scripts/verify-connector-routing/verify.sh`; the kind rehearsal `kind.sh` beside it.

| Record | Where | Commit | Result |
|---|---|---|---|
| [kind-2026-11-21.md](kind-2026-11-21.md) | kind (`kind-ztd-rt`): a peer entry outside the cluster, the egress role routed to it, zone B's hand-applied entry adopted by the ingress role | `bb6f42c6` | rehearsal 7/7, proof 15/15 PASS; the adoption lost 1 of 39 calls (the hand-applied pod has no preStop pause), a later rollout of the chart's entry none of 38 |
| [zone-b-entry-adoption-2026-11-21.md](zone-b-entry-adoption-2026-11-21.md) | `zerotrust-b`: the entry `ztd-edge` adopted by release `ztd-edge` | `895531dc` | guarded path PASS before and after; Service UID, node port and address unchanged; 42 of 42 outside calls served during the change |
| [zone-a-2026-11-21.md](zone-a-2026-11-21.md) | `zerotrust-a`: release `ztd-connector-gateway` in `ztd-data`, routed to zone B's entry | `bb6f42c6` | 11/11 PASS: the guarded `POST /demo` from zone A served through both Connector components (outcome `success`), logged by the gateway and by zone B's entry; the direct attempt dropped (Hubble policy drop) and absent from the entry's log; an impostor refused by the gateway's proxy; DNS and the export lane |
| [zone-b-2026-11-21.md](zone-b-2026-11-21.md) | `zerotrust-b`: the ingress role | `bb6f42c6` | 10/10 PASS: the entry forwards to one upstream; the only exposed Services are the entry and the declared TRAIN DNS listener; the data plane reaches none of the M3 services and nothing outside the cluster; DNS and the export lane |
| [plane-separation-zone-a-2026-11-21.md](plane-separation-zone-a-2026-11-21.md) | `zerotrust-a` with the gateway installed | `bb6f42c6` | 71 pass, 0 fail, 5 n/a (destinations without a proxy), 1 declared (istiod xDS, proposed): the gateway is probed as a data-plane destination and refused from every management-plane namespace at both layers |
| [plane-separation-kind-2026-11-21.md](plane-separation-kind-2026-11-21.md) | kind with the gateway installed | `895531dc` | 67 pass, 0 fail, 6 n/a, 1 declared; the same classifications |

Live state left in place: zone A `ztd-data` runs release `ztd-connector-gateway` (its peer, zone B's entry
address and CA, given at install, not committed); zone B `ztd-m3-b` runs release `ztd-edge`. Rollback, in
fail-closed order: zone A, scale the gateway to 0 (routing stops), then uninstall the release (its policies
go; the namespace default deny stays); zone B, as in the adoption record.

Not shown here: the observability export to a real collector (no collector runs on the zones; the export
lane is proven with a stand-in carrying the row's labels and identity); the inter-zone transport is TLS over
public transit, not the attested channel ([Specifications](../../specifications.md)).
