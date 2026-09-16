# Orchestrated flows

Functional breakdown of the ORCE flows in `flows/` and the Builder nodes in `ui/`.

## Structure

Flows follow the work-sample pattern supplied with the tender: one message contract, a dispatcher
that only routes, validation on the server side, and a clean separation between session, step,
model, UI and error concerns.

Every step records an explicit result. A step that fails mid-flow lands in a defined error state
rather than leaving a journey without an outcome.

## Contents

- **Flow inventory** — each journey, its trigger and its steps.
- **Builder node UI and parameter documentation** — the custom nodes in `ui/`, their inputs,
  outputs and configuration.
- **Governed configuration** — how a flow or configuration change is previewed, validated against
  JSON Schema and SHACL, applied as a pull request, and rolled back.
