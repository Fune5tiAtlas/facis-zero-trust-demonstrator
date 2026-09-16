# Keycloak integration

Keycloak is the demonstrator's identity provider and is used as a **stock product** — the custom
OAuth2 surface lives in the Go connector instead, precisely so that Keycloak is never forked. See
[ADR-0003](adr/0003-oauth2-authorisation-surface-in-the-go-connector.md).

## Contents

- **Realm as code** — clients, roles, scopes and demonstration personas, exported to Git and applied
  by pipeline so the realm reproduces from scratch.
- **OIDC login** — the redirect flow into the demonstrator UI, role claims gating which actions a
  viewer may trigger, logout, and the explicit expired and denied states.
- **Connector boundary** — what Keycloak issues versus what the connector issues, and why.
