# Features and journeys

> **Status:** structure established. Each section below is filled as the corresponding capability
> lands; the headings are the agreed shape, not placeholders to be renamed.

## The successful journey

A participant backend in zone A calls a protected resource in zone B. Every hop is checked:
workload identity in the mesh, admission control on what was allowed to run at all, a policy
decision at the guard, an attested channel between the zones, and a token that was minted against a
verified credential presentation rather than a shared secret.

## The refusal journeys

The demonstrator treats denials as first-class demonstrations, because a zero-trust system that only
shows the happy path has not shown anything:

- a **revoked credential** — verification flips negative, the grant refuses, the token store fails
  closed;
- a **wrong scope** — the guard denies and returns the reason and an OID4VP link;
- a **tampered measurement** — the attested handshake aborts before any traffic flows.

## Capability map

| Capability | Where it lives |
|---|---|
| Workload identity and service mesh | `deployment/helm/` |
| Admission control and supply chain | `deployment/helm/`, `.github/workflows/` |
| Connector authorization services | `services/` |
| Guard and policy | `services/` |
| Attested inter-cluster channel | `services/` |
| Credentials and trust integration | `deployment/helm/` |
| Demonstrator UI and orchestration | `services/` |
