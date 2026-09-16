# API documentation

> **Status:** structure established. Specifications are added here as each service's interface is
> frozen.

## Interface registry

The demonstrator's cross-component interfaces are identified as `IF-01` through `IF-08` and frozen
at v1 before the components that consume them are built. Each entry below links to its machine-
readable definition once published.

| Interface | Purpose | Definition |
|---|---|---|
| IF-01 | Security-state event stream to the demonstrator UI | _to be published_ |
| IF-02 | Connector authorization surface (registration, token issuance) | _to be published_ |
| IF-03 | Credential verification outcome | _to be published_ |
| IF-04 | Observability and evidence | _to be published_ |
| IF-05 | Policy decision input and output | _to be published_ |
| IF-06 | Governed configuration change | _to be published_ |
| IF-07 | Attested channel control | _to be published_ |
| IF-08 | Scenario driver hooks | _to be published_ |

## Conventions

- REST APIs are described with OpenAPI 3; asynchronous interfaces with JSON Schema.
- Structured data carries a JSON-LD context and a SHACL shape where the content is meant to be
  interoperable rather than internal.
- Error responses use a shared reason-code vocabulary, so a refusal is machine-readable and not
  just a status code.
