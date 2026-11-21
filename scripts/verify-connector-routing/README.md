# verify-connector-routing

The ZT-26 proof (BDD-ZT-026) of the Zero Trust Connector routing in
[Architecture §6](../../docs/architecture.md#zero-trust-connector-routing-zt-26): application traffic
crosses the zone boundary through the connector gateway only, the direct paths around it are refused, and
the declared bypasses (name resolution, observability export) work over their own paths. It runs against
an installed zone and installs nothing; its stand-ins (`fixtures/stand-ins.yaml`, and
`fixtures/otel-stand-in.yaml` where no collector runs) are removed on exit. Each check's outcome class is
read from curl's own exit code, as the other cluster proofs do (`scripts/lib/probe.sh`); a network drop
cites Hubble's policy drop when the node's Cilium agent answers `hubble observe`.

| Section | Runs when | Passes when |
|---|---|---|
| egress-route | the gateway `GATEWAY` exists in `ROUTE_NAMESPACE` | its NetworkPolicy has one egress lane; the caller's request through it is served by the peer; the gateway's access log records it with the peer as upstream; the peer's log (`PEER_LOG_CMD`) records its arrival; an impostor with the caller's labels is refused by the gateway's proxy (403 and a denial line naming it) |
| direct-path | always | the caller's direct attempt at the peer entry and at each `DIRECT_EXTERNAL` is dropped (and absent from the peer's log); each `DIRECT_TARGETS` Service is unreachable |
| entry | `ENTRY_NAMESPACE`, `ENTRY_NAME` | the entry forwards to one upstream; every `LoadBalancer`/`NodePort` Service of the cluster is the entry or in `DECLARED_ENTRIES` |
| exemptions | always | the caller resolves cluster names; it reaches the collector (or a stand-in with the export row's labels and identity) on 4318 |

On a participant cluster the context guard of `scripts/lib/proof.sh` applies (`ZTD_CONFIRM_CLUSTER`), and
the record is masked of addresses. Zone A (egress role):

```bash
KUBECONFIG=<zone A> KUBE_CONTEXT=zerotrust-a ZTD_CONFIRM_CLUSTER=zerotrust-a \
ROUTE_METHOD=POST ROUTE_PATH=/demo ROUTE_BODY='{"resource":"sample-report","action":"read"}' ROUTE_EXPECT='"outcome":"success"' \
PEER_LOG_CMD='kubectl --kubeconfig <zone B> -n ztd-m3-b logs deploy/ztd-edge -c envoy' \
scripts/verify-connector-routing/verify.sh
```

Zone B (ingress role; no gateway): `ENTRY_NAMESPACE=ztd-m3-b ENTRY_NAME=ztd-edge
DECLARED_ENTRIES=ztd-train/train-zone-manager-dns DIRECT_TARGETS='ztd-m3-b/ztd-protected-resource:8080
ztd-m3-b/ztd-guard:8080 ztd-m3-b/ztd-participant:8080' DIRECT_EXTERNAL=<an address outside the zone>:443`.

`kind.sh` rehearses both roles on a kind zone (`scripts/dev/kind-cilium-up.sh`, then
`scripts/install-zone/install.sh install ztd spire-crds spire istio-base istiod istio-cni zone-policy`):
a peer entry in a container on the kind network, the egress release routed to it, zone B's hand-applied
entry adopted by the chart under a client calling it every half second, then this proof on both.
