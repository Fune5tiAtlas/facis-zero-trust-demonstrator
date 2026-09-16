# BDD acceptance specifications

Every acceptance requirement is expressed as an executable scenario, tagged with the requirement it
covers, so that traceability from requirement to test is generated rather than maintained by hand.

## Conventions

- Feature text quotes the acceptance wording verbatim, so a scenario can be matched to its
  requirement at a glance.
- Each scenario carries a tag naming its requirement.
- Scenarios run both in CI and against live clusters.
- Negative cases assert against the audit entry that recorded the refusal, not merely against a
  failed response.

## Evidence

Each gate produces one indexed evidence bundle, assembled by a single command, with a directory per
requirement row. Bundles are versioned and immutable once a gate has consumed them.
