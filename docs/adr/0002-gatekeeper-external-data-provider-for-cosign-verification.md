# ADR-0002: Gatekeeper external-data provider for Cosign signature verification

- **Status:** Accepted
- **Date:** 2026-09-08
- **Deciders:** Technical Design Authority (Kevin Kupilas)
- **Requirement basis:** ZT-10, ZT-12, ZT-37, ZT-54
- **Follow-up requirement:** F-05

## Context

Admission control must refuse container images whose Cosign signature cannot be verified against the client
key material. OPA Gatekeeper cannot perform signature verification itself; it delegates to an external-data
provider. Two options exist: Ratify v1, an established provider from the CNCF ecosystem, or a first-party Go
provider written for this project.

The project constraints matter here: Go is the prescribed language for services other than the ORCE Builder
logic, deployment must be Helm-based and idempotent, and every refusal must produce a machine-readable reason
that the ORCE demonstrator can display.

## Decision

A **first-party ATLAS Go external-data provider** is the implementation baseline. Ratify v1 remains the
documented fallback.

The provider verifies Cosign signatures against the client-supplied key material, returns a structured
decision with a stable reason code, and is packaged as a Helm chart alongside the Gatekeeper deployment.

## Consequences

- Positive: the refusal reason is emitted in the project's own error taxonomy and correlates directly with the
  ORCE decision view, without translating a third-party error model.
- Positive: no additional third-party licence or supply-chain dependency in the admission path.
- Negative: the project owns the maintenance of a security-critical component. Mitigation: the provider is
  small, its scope is limited to signature verification, and it is covered by positive and negative admission
  scenarios in Annex A.
- The final implementation choice remains subject to the architecture assessment and, where required, FACIS
  confirmation. If the assessment favours Ratify v1, this ADR is superseded rather than amended.

## References

- Annex A v1.7 — ZT-10, ZT-12, ZT-37, ZT-54
- Project Plan v1.7, section 4 — Gatekeeper external-data provider
