# OSS dependencies and external references

Third-party components the demonstrator depends on, and the upstream projects it integrates with
but does not own.

## Licence compliance

Every dependency clears Eclipse Dash before it ships. A dependency under a licence the project
cannot accept is replaced, not waived; anything Dash cannot clear automatically goes to the Eclipse
IP team for review. See [CI/CD](ci-cd.md).

Generated inventories — the CycloneDX SBOM and the Dash summary — are published with each release
and are the authoritative list. This page records the components chosen and why.

## External XFSC components

The demonstrator integrates XFSC components rather than reimplementing them: the Trust Services API
for policy evaluation, the Organisation Credential Manager for wallets, TRAIN for trust anchoring,
and ORCE for orchestration. Versions are pinned at deployment and recorded with the release.
