# Troubleshooting

Symptoms, causes and checks for the demonstrator.

## Reading a refusal

The demonstrator is built so that a refusal explains itself. Before debugging, read the denial: the
guard returns the layer and the rule that produced the decision, and the matching audit entry
carries the same reason code. A refusal with a reason is working as designed — the question is
whether the reason is the one you expected.

## Contents

- Workload identity and mesh enrolment
- Admission control rejections
- Token issuance, DPoP proofs and the token store
- Attested channel handshake failures
- Credential verification and trust-list staleness

## Logs

Services emit structured JSON logs. Correlate by the request identifier carried across hops rather
than by timestamp.
