# Troubleshooting

Symptoms, causes and checks for the demonstrator.

## Reading a refusal

The demonstrator is built so that a refusal explains itself. Before debugging, read the denial: the
guard returns the layer and the rule that produced the decision, and the matching audit entry
carries the same reason code. A refusal with a reason is working as designed — the question is
whether the reason is the one you expected.

## Workload identity and mesh enrolment

| Symptom | Likely cause | Check |
|---|---|---|
| A pod starts but no traffic reaches it | It never received an SVID, so the mesh has no identity to route to | Look for a SPIRE registration entry matching the pod's service account; a missing entry is the answer, not a mesh problem |
| The SVID exists but the SPIFFE ID is wrong | The registration selector matches more, or less, than intended | Compare the SPIFFE ID in the workload's certificate with the selector that produced it |
| Traffic works between two pods that should not be able to talk | L7 enforcement is owned by neither component on that path, or by both | Check which component owns L7 for that path in the mesh configuration — [ADR-0001](adr/0001-service-mesh-mode-istio-ambient-with-cilium.md) requires exactly one |
| The Istio CNI plugin never chains | Cilium claimed the CNI configuration exclusively | Confirm Cilium is installed with `cni.exclusive=false` |

## Admission control rejections

| Symptom | Likely cause | Check |
|---|---|---|
| An image will not start and the event is generic | Gatekeeper refused it but the reason did not reach the event | Read the provider's decision, which carries the reason code; a refusal with no reason code is a defect in the provider |
| A correctly signed image is refused | The verification key does not match the key the image was signed with | Compare the signing key used by the pipeline with the key material the provider was configured with |
| An unsigned image starts | The constraint is not bound to that namespace, or the provider is not reachable | Confirm the constraint's scope, then confirm the provider answers — an unreachable provider must fail closed, not open |

## Token issuance, DPoP proofs and the token store

| Symptom | Likely cause | Check |
|---|---|---|
| Registration succeeds but no token is issued | The presentation did not verify, so there is nothing to derive a token from | Read the verification outcome first; the token failure is downstream of it |
| A token is rejected on use | The DPoP proof is not bound to the key that requested the token, or is being replayed | Compare the proof's key thumbprint with the one recorded at issuance |
| The upstream call carries the caller's own token | Substitution did not happen | Trace the outbound request — the caller's proof must never be forwarded onward |
| Everything fails after a control-plane blip | The token store failed closed, as designed | Confirm the alert was raised; fail-secure is the correct behaviour, silence is not |

## Attested channel handshake failures

| Symptom | Likely cause | Check |
|---|---|---|
| The handshake aborts | The peer's measurement does not match the expected value | Compare the report's measurement with the expected value resolved from TRAIN; a mismatch is a working refusal |
| The handshake aborts and the expected value is absent | The trust-list entry is missing or stale, not the peer | Resolve the peer's digest through TRAIN directly before suspecting the peer |
| The report verifies but the channel is refused | The evidence is not bound to this connection | Confirm the TLS exporter value is present in the report's user data — an unbound report is a replay risk, so refusal is correct |
| Application traffic appears after a failed handshake | A serious defect | This must be impossible and is asserted by an acceptance scenario; treat any instance as a stop-the-line finding |

## Credential verification and trust-list staleness

| Symptom | Likely cause | Check |
|---|---|---|
| A credential that worked yesterday is refused | It was revoked | Check the status list entry before anything else |
| Verification fails for every credential at once | The status list or the trust anchor is unreachable | Check reachability; an unreachable list must deny, and the alert tells you which one it was |
| A peer that should be trusted is not listed | The trust list has not been republished since the peer was added | Compare the published trust list with what the connector resolved, not with what you expect it to contain |

## Logs

Services emit structured JSON logs. Correlate by the request identifier carried across hops rather
than by timestamp.
