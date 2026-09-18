# Orchestrated flows

Functional breakdown of the ORCE flows in `flows/` and the Builder nodes in `ui/`.

## Structure

Flows follow the work-sample pattern supplied with the tender: one message contract, a dispatcher
that only routes, validation on the server side, and a clean separation between session, step,
model, UI and error concerns.

Every step records an explicit result. A step that fails mid-flow lands in a defined error state
rather than leaving a journey without an outcome.

## Flow inventory

| Flow | Trigger | Steps | Ends in |
|---|---|---|---|
| Successful call | Operator starts the journey from the UI | Backend registers → credential presented → token issued and DPoP-bound → attested channel established → guard permits → resource responds | Resource payload shown, every step green |
| Revoked credential | Operator revokes the credential, then starts the journey | Presentation verified → status list consulted → verification negative → grant refused → token store fails closed | Refusal with the revocation reason |
| Wrong scope | Operator starts the journey with a persona lacking the scope | Token issued → guard evaluates policy → no matching rule | Denial carrying the rule, the reason code and an OID4VP link |
| Tampered measurement | Operator alters the expected measurement | Attestation requested → report returned → expected and actual compared → mismatch | Handshake aborted, with the proof that no application traffic passed |
| Credential issuance | Operator starts the issuing journey | Wallet receives the credential from the OCM W-Stack → credential unlocks the protected resource on the next call | Previously refused call now permitted |
| Configuration change | Operator edits a trust zone or a policy in the UI | Change previewed → validated → applied as a pull request → effect visible on the next journey | Journey outcome changes, with the change traceable to its pull request |

Each step reports its own result to the UI, so a journey that fails halfway shows *where* it
stopped, not merely that it stopped.

## Builder node UI and parameters

The custom Builder nodes live in `ui/`. Each node is documented with the same four things, so a node
can be configured without reading its source:

| Field | Meaning |
|---|---|
| Purpose | What the node does in one sentence, and which journey step it serves |
| Inputs | The message properties it reads, and which are required |
| Outputs | The message properties it sets, including the result and reason code |
| Configuration | Editor parameters, their types, defaults and validation |

A node that alters the security outcome of a journey does not decide it: the decision stays on the
connector and guard path, and the node reports it. This is the same boundary
[ADR-0003](adr/0003-oauth2-authorisation-surface-in-the-go-connector.md) draws for the
authorisation surface.

## Governed configuration

Flows and demonstrator configuration are data, and they are governed like code rather than edited
live:

1. **Preview** — the change is shown as a diff against the running configuration before anything is
   applied.
2. **Validate** — structure is checked against JSON Schema, and interoperable content against its
   SHACL shape. Invalid configuration is refused at this step, not at runtime.
3. **Apply** — the change lands as a pull request against this repository, so it carries a review
   and an author.
4. **Roll back** — reverting the pull request restores the previous configuration; no state lives
   only in a running editor.

An export of a flow is therefore reproducible: the same repository and the same values produce the
same journey.
