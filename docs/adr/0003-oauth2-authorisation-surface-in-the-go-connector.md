# ADR-0003: OAuth2 authorisation surface implemented in the Go Connector

- **Status:** Accepted
- **Date:** 2026-09-08
- **Deciders:** Technical Design Authority (Kevin Kupilas), Deputy Project Leader (Daniel Pires)
- **Requirement basis:** ZT-21, ZT-22; SRS identity and credential requirements
- **Follow-up requirement:** F-05

## Context

ZT-21 and ZT-22 require Dynamic Client Registration, tokens derived from an OID4VP presentation, and
DPoP-bound token storage. Keycloak is the prescribed identity provider, but the mapping from a verified
credential presentation to a DPoP-bound access token is specific to the Zero Trust enforcement path and is not
covered by a standard Keycloak flow. Placing that mapping inside Keycloak would mean custom extensions in the
identity provider; placing it in the Connector keeps the identity provider stock.

## Decision

The OAuth2 authorisation surface — Dynamic Client Registration, OID4VP-derived token issuance and DPoP-bound
token storage — is **implemented in the Go Connector**. Keycloak remains the identity provider for realm,
client, role and scope management and is used unmodified.

The authoritative allow/deny decision stays on the Connector and enforcement path. No component outside that
path derives, reinterprets or overrides it.

## Consequences

- Positive: Keycloak stays a stock deployment, provisioned as code and reproducible; no custom provider or SPI
  to maintain across Keycloak versions.
- Positive: token binding and the enforcement decision live in the same component, so replay, DPoP mismatch,
  token substitution and failed renewal are testable as one negative-path suite.
- Negative: the Connector carries more authorisation logic than a plain proxy would, which raises its review
  burden. Mitigation: the OAuth2 surface is reviewed by the Technical Design Authority and covered by explicit
  negative scenarios in Annex A.

## References

- Annex A v1.7 — ZT-21, ZT-22
- Project Plan v1.7, section 4 — OAuth2 authorisation surface
