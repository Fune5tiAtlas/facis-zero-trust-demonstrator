# FACIS Zero Trust Demonstrator

This is the documentation for the FACIS Zero Trust Demonstrator (FACIS.ZTD), an Apache-2.0
demonstrator released inside the Eclipse XFSC organisation.

The demonstrator stands up two demonstration zones and lets a participant backend in one zone call
a protected resource in the other, with every hop authenticated, authorised and attested. It is
built to show the refusals as clearly as the successes: a revoked credential, a wrong scope or a
tampered measurement each produce a distinct, explained denial.

## Where to start

| If you want to | Read |
|---|---|
| Understand what the demonstrator does | [Features and journeys](features.md) |
| Stand it up or tear it down | [Deployment](deployment.md) |
| Know how it is built and shipped | [Packaging and containers](packaging.md) |
| Follow the orchestrated journeys | [Orchestrated flows](flows.md) |
| Wire up identity | [Keycloak integration](keycloak.md) |
| Call its APIs | [API documentation](api-docs.md) |
| See how acceptance is proven | [BDD acceptance](bdd.md) |
| Understand the pipeline | [CI/CD](ci-cd.md) |
| Diagnose a problem | [Troubleshooting](troubleshooting.md) |
| Check what it depends on | [OSS dependencies](dependencies.md) |
| Find where we depart from the specification | [Specification changes](specifications.md) |
| Understand why it is built this way | [Architecture decisions](adr/index.md) |

## Project context

FACIS.ZTD is delivered for the FACIS project and published in Eclipse XFSC. The wider FACIS
programme — Federation Architecture Patterns, machine-readable SLAs, digital contracting and the
other demonstrators — is indexed at
[eclipse-xfsc/facis](https://github.com/eclipse-xfsc/facis).

## Licence

Apache License 2.0. `SPDX-License-Identifier: Apache-2.0`
