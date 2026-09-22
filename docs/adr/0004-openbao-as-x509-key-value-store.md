# ADR-0004: OpenBao as the X.509 key-value store under ZT-11

- **Status:** Accepted, pending FACIS licence decision
- **Date:** 2026-09-08
- **Deciders:** Project Leader (Robert Koning), Technical Design Authority (Kevin Kupilas)
- **Requirement basis:** SRS ZT-11 (spelled "ObenBao" in the SRS)
- **Follow-up requirements:** F-05, F-07

## Context

ZT-11 prescribes a key-value store for the X.509 storage path. The component named in the SRS is OpenBao,
which is licensed MPL-2.0. Every other runtime component in the baseline is Apache-2.0, and the Technical
Development Requirements require a formal written exception for any non-Apache licence.

## Decision

**OpenBao is used as prescribed by ZT-11.** It is deployed as a cluster-internal service, consumed unmodified
through its API, and never linked into a project deliverable. A formal written licence exception has been
submitted to FACIS (Licence Exception Notice v1.0, follow-up requirement F-07).

The exact version and deployment approach remain subject to written FACIS confirmation and to verification
against the current Eclipse approved-licences list.

## Consequences

- Positive: the prescribed component is used, so no deviation from the SRS has to be argued at acceptance.
- Negative: the delivery baseline depends on a FACIS decision that is not yet given. If the exception is
  declined, a replacement for the ZT-11 storage path must be agreed with FACIS, since the component itself is
  prescribed — this is a scope question, not an implementation choice, and would be escalated under the change
  rule in Project Plan v1.7, section 1.
- MPL-2.0 is file-level copyleft. Because OpenBao is deployed as a separate unmodified service, its obligations
  do not extend to newly developed project components, which remain Apache-2.0 under SRS 2.3.2.

## References

- SRS ZT-11
- Licence Exception Notice v1.0
- Project Plan v1.7, section 4 — OpenBao
