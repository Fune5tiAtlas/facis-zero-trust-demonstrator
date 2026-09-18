# Keycloak integration

Keycloak is the demonstrator's identity provider and is used as a **stock product** — the custom
OAuth2 surface lives in the Go connector instead, precisely so that Keycloak is never forked. See
[ADR-0003](adr/0003-oauth2-authorisation-surface-in-the-go-connector.md).

## Realm as code

The realm is not configured by hand in the admin console. Clients, roles, scopes and the
demonstration personas are held as a realm export in this repository and applied by the pipeline, so
that a fresh cluster reaches the same identity configuration as the last one.

| Held in Git | Not held in Git |
|---|---|
| Realm settings, clients, roles, scopes, client scopes | Client secrets and any key material |
| The demonstration personas and their role assignments | Runtime sessions and tokens |
| Login theme selection and required actions | Anything a viewer creates during a demonstration |

Secrets are injected at apply time from OpenBao. A realm export containing a secret is a defect —
the export is committed, so what is in it is public.

## OIDC login

The demonstrator UI authenticates its **viewer** — the person driving the demonstration — through
the standard OIDC redirect flow against Keycloak. Role claims from the resulting token gate which
actions that viewer may trigger, so that a read-only observer cannot revoke a credential or tamper
with a measurement mid-demonstration.

Three states are shown explicitly rather than being allowed to look like a fault:

- **expired** — the session ended; the UI says so and offers re-authentication;
- **denied** — the viewer is authenticated but lacks the role for the action they clicked;
- **logged out** — the session is cleared at both ends, not only in the browser.

## Connector boundary

This is the distinction that matters, and it is the reason Keycloak is never forked:

| Keycloak issues | The Go connector issues |
|---|---|
| Identity for **people** — the viewer driving the demonstrator UI | Authorization for **machines** — the participant backend calling a protected resource |
| Realm, client, role and scope management | Dynamic Client Registration for participant backends |
| Standard OIDC tokens for the UI session | Access tokens derived from a verified OID4VP presentation, DPoP-bound |

The authoritative allow/deny decision for a protected resource stays on the connector and guard
path. Keycloak is not asked to reinterpret it, and nothing outside that path overrides it. The
reasoning, including why Keycloak's own DPoP and OID4VCI support is not depended on, is in
[ADR-0003](adr/0003-oauth2-authorisation-surface-in-the-go-connector.md).
