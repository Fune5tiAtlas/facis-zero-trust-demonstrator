# Changes and additions to source specifications

Where the implementation departs from, or adds to, the Software Requirements Specification and the
Technical Development Requirements — and why.

Each entry records the specification clause, what changed, the reason, and the decision record that
governs it. Architecture decisions themselves live in [`adr/`](adr/index.md); this page is the index
from specification clause to decision, so a reviewer can start from the requirement rather than from
the decision.

## Readings and additions

| Specification clause | What the implementation does | Reason | Decision |
|---|---|---|---|
| SRS 2.3.3 — secure service mesh with SPIFFE/SPIRE, mode unspecified | Istio **Ambient** with Cilium as CNI, `cni.exclusive=false`, one named L7 enforcement owner per traffic path | The SRS fixes the identity model but not the data-plane mode; leaving it unfixed would put mesh and CNI in contention for L7 enforcement | [ADR-0001](adr/0001-service-mesh-mode-istio-ambient-with-cilium.md) |
| ZT-10, ZT-12, ZT-37 — admission must refuse unsigned images | A first-party Go external-data provider verifies Cosign signatures for OPA Gatekeeper; Ratify v1 is the documented fallback | Gatekeeper cannot verify signatures itself and the upstream provider is archived, so the component has to be built rather than adopted | [ADR-0002](adr/0002-gatekeeper-external-data-provider-for-cosign-verification.md) |
| ZT-21, ZT-22 — DCR, OID4VP-derived tokens, DPoP-bound storage, with Keycloak as identity provider | The OAuth2 authorisation surface is implemented in the Go Connector; Keycloak is used unmodified for realm, client, role and scope management | Keycloak's DPoP support is preview and OID4VCI experimental; the authoritative decision stays on the enforcement path rather than depending on preview features | [ADR-0003](adr/0003-oauth2-authorisation-surface-in-the-go-connector.md) |
| ZT-11 — key material stored in OpenBao | OpenBao is used as prescribed, deployed as a cluster-internal service and consumed unmodified through its API | OpenBao is MPL-2.0 where the rest of the baseline is Apache-2.0; a written licence exception was submitted rather than the component silently swapped | [ADR-0004](adr/0004-openbao-as-x509-key-value-store.md) · [licence exception](dependencies.md#licence-exceptions) |
| SRS 2.4.1 and SRS 2.7 — two cloud environments, plus a dedicated CI/CD environment on IONOS | Three managed clusters: two on T-Systems Open Sovereign Cloud, one on IONOS with its own CI/CD | Read strictly the two clauses give different cluster counts, and the count drives the per-cluster installation effort and the trust-zone topology | [ADR-0005](adr/0005-three-cluster-reading-of-the-target-environment.md) |
| SRS 2.6.2 — assumes Grafana plugins for observability, and permits another technology | Grafana is not shipped; visualization is the demonstrator UI plus the Prometheus and Jaeger interfaces | Grafana's core has been AGPL-3.0 since v8, which breaches the Apache-2.0-compatibility rule; the SRS's own alternative clause is taken | [licence exception](dependencies.md#licence-exceptions) |
| ZT-34 — the reverse proxy accepts Ingress or Gateway API resources as configuration | A `GatewayClass`-scoped operator translates Gateway and HTTPRoute resources into proxy configuration | The clause asks for resources-as-configuration, not a conformant Gateway API implementation; scoping to a GatewayClass keeps the operator small and the scope agreed | pending confirmation |
| ZT-31, ZT-71 — mock attestation in JSON for any TEE vendor | Evidence is produced by the CMC software driver in a vendor-agnostic report envelope; CMC's own evidence and collateral types are reused unmodified, with one sample artefact per vendor profile in `attestation/samples/` | No TEE hardware is in scope; the mock has to be honest about being a mock and carry the same structure a real driver would emit | [mock-attestation.schema.json](attestation/mock-attestation.schema.json) |

## Deviation status

Every reading above is declared rather than assumed. The five governing ADRs were submitted to FACIS
as the F-05 deviation package and the OpenBao licence exception as F-07; both are open at the time of
writing. A reading that FACIS declines is handled as a plan change under the written-agreement rule,
not absorbed into the implementation.
