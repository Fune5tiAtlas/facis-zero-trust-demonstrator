# Using the demonstrator

What the demonstrator shows, how to drive it, and how to read what it tells you. This is the manual
for someone standing in front of a running deployment — [Deployment](deployment.md) gets you there,
and the [environment guides](environments/index.md) cover the specific clusters.

## What you are looking at

Two demonstration zones, each a Kubernetes cluster with its own workload identity, admission
control and policy enforcement. A participant backend in zone A calls a protected resource in
zone B. Nothing about that call is taken on trust: the workload proves what it is, the image it runs
was admitted only because its signature verified, the channel between the zones is established only
if both ends attest to the software they are running, and the request itself is authorised against a
credential the caller presented rather than a secret both sides happen to know.

The demonstrator UI shows each of those checks as it happens, including the ones that fail.

## Driving it

Every journey is started from the demonstrator UI, which is an ORCE flow rather than bespoke
application code — so what you see on screen is the orchestration itself, and each step in the flow
corresponds to a step on screen.

| Journey | What it demonstrates |
|---|---|
| Successful call | Workload identity, admission, attested channel, credential-derived token, policy allow |
| Revoked credential | Verification flips negative, the grant refuses, the token store fails closed |
| Wrong scope | The guard denies, returns a reason code and an OID4VP link to obtain what is missing |
| Tampered measurement | The attested handshake aborts before any application traffic flows |

The three refusals are first-class: they are the point of the demonstrator, not error handling shown
by accident. Each is triggered deliberately from the UI.

## Reading a result

Every decision the demonstrator makes carries the same three things, whichever component made it:

- **a stable reason code** — the same code for the same condition, so a refusal can be looked up
  rather than interpreted;
- **the identity it was made about** — the SPIFFE identity of the workload, or the credential
  subject, not an IP address;
- **an audit entry** — written whether the answer was allow or deny.

A refusal that produces no audit entry is a defect, not a quiet success. The acceptance scenarios
assert the audit entry for every negative case.

## What is mocked and what is not

The Trusted Execution Environment is mocked: there is no TEE hardware in scope, so attestation
evidence is produced in software in the same report structure a real driver would emit. The
demonstration services either side of the call are purpose-built.

Everything else — the mesh identity, the admission control, the signature verification, the policy
evaluation, the credential verification, the attested channel and its binding to the TLS connection
— is the real machinery, doing the real work.

## Generating the manual

This page and the rest of `docs/` are published to GitHub Pages by
[`docs.yml`](ci-cd.md#documentation-publication) on every change to `main`, so the current manual is
always the one built from the current source. ZT-17 requires the manual to be generatable over
GitHub Actions; the site build is that generator.
