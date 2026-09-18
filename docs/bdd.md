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

## Scenario inventory

The scenarios are grouped by the part of the architecture they exercise. Each family carries the
requirements it proves and the negative case it must include — a family with no negative case is
incomplete, because the demonstrator's claim is about what it refuses.

| Family | Requirements | Positive case | Negative case it must include |
|---|---|---|---|
| Workload identity | ZT-24, ZT-57, ZT-59, ZT-60 | A workload attests and receives an SVID whose SPIFFE ID matches its service account | Failed attestation yields no identity **and** no mesh connectivity |
| Mesh enrolment and segmentation | ZT-01, ZT-23, ZT-25, ZT-26, ZT-58, ZT-61, ZT-62 | All service traffic is routed through the mesh; only configured identities may talk | An unaffiliated workload is refused, and the refusal is not IP-based |
| Management/data plane separation | ZT-49, ZT-53, ZT-55 | The management plane is unreachable from the data plane | A data-plane workload attempting a management-plane call is denied at the network layer |
| Admission control | ZT-02, ZT-11, ZT-36, ZT-37, ZT-72 | A correctly signed image is admitted | An unsigned or wrongly signed image is refused, with the reason code in the admission log |
| Supply chain | ZT-10, ZT-13, ZT-38, ZT-54, ZT-71 | Images build on the runner, are signed by digest, and ship an SBOM and a mock attestation | A non-Linux image, or one missing its signature, fails the pipeline |
| Attested channel | ZT-04, ZT-28…ZT-33, ZT-63…ZT-69 | Both ends attest, the verdict is machine-readable, and application traffic follows | A tampered measurement aborts the handshake — and it is **proven** no application traffic passed (ZT-70) |
| Expected measurements and trust lists | ZT-03, ZT-18, ZT-35, ZT-64 | Peer digests resolve through TRAIN and match | A stale or absent trust-list entry refuses the peer |
| Authorization surface | ZT-20, ZT-21, ZT-22, ZT-39, ZT-73, ZT-76 | Dynamic registration, a token derived from a verified presentation, DPoP-bound and substituted upstream | A replayed or unbound DPoP proof is rejected; a wrong scope is denied with an OID4VP link |
| Credential lifecycle | ZT-40, ZT-51 | A credential is issued to the wallet and unlocks the protected resource | A revoked credential flips verification negative and the token store fails closed |
| Policy decision | ZT-06, ZT-20, ZT-41, ZT-75 | The guard permits on a matching policy and returns the resource | No matching policy denies, with the rule and reason recorded |
| Fail-secure behaviour | ZT-47, ZT-52 | Each request is authorised on its own merits | Control-plane unavailability denies rather than admits, and raises an alert |
| Visualization and journey | ZT-05, ZT-08, ZT-09, ZT-43, ZT-44, ZT-78, ZT-81 | The ORCE journey runs end to end and each step is visible | Every refusal above is visible in the UI, not only in a log |
| Documentation and reproduction | ZT-16, ZT-17 | Each cluster is reproduced from the [environment guides](environments/index.md) alone | A step that cannot be reproduced from the documentation fails the check |

## Traceability

Each scenario's tag is its requirement id, so the requirement-to-test matrix is generated from the
feature files rather than maintained beside them. A requirement with no tagged scenario shows up as
a gap in that matrix; that is the point of generating it.

## Evidence

Each gate produces one indexed evidence bundle, assembled by a single command, with a directory per
requirement row. Bundles are versioned and immutable once a gate has consumed them.
