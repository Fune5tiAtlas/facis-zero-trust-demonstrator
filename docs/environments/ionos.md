# IONOS Cloud — CI/CD and visualization

The third cluster. It runs the delivery machinery and the visualization surface, and deliberately
holds no demonstration workload: nothing that participates in a zone-to-zone call runs here, so a
failure in the pipeline cannot be mistaken for a failure in the demonstrator.

!!! note "Status"
    Written from the platform baseline and the decisions that govern it. The cluster is
    client-provided and was not yet available when this page was written, so every step is marked
    with how it is verified, and the page is confirmed against a real cluster on first stand-up.

## Before you start

You need:

- a kubeconfig for the IONOS cluster with rights to create namespaces and cluster-scoped resources;
- the container registry credentials the pipeline pushes with, as a robot account rather than a
  personal one;
- the signing key material, and authorisation for the runner to use it — the pipeline signs by
  digest and will not run unsigned;
- this repository checked out.

Same floor as everywhere else:

```bash
kubectl version -o json | jq -r '.serverVersion.gitVersion'
```

## 1. CNI

As on the OSC clusters, Cilium with `cni.exclusive=false`. The visualization environment is meshed
too, so its traffic is subject to the same identity rules as anything else.

**Verify:** every Cilium pod is `Running` and `cilium status` reports the cluster healthy.

## 2. The build and signing runner

The AMD64 Linux runner is registered here and is the only place project images are built and signed.
Key custody follows the arrangement agreed with the client, and the workflows that can use the key
are restricted by a GitHub environment protection rule rather than by convention.

**Verify:** the runner appears as online and correctly labelled, a test build produces a
`linux/amd64` image, and a signing job that is not launched from a protected workflow is refused.

## 3. Registry access

The pipeline pushes images and their signatures to the client's Harbor registry, and the clusters
pull from it.

**Verify:** the robot account can push and the OSC clusters can pull, using a throwaway tag rather
than a release artefact.

## 4. Visualization

The demonstrator UI and the observability interfaces — Prometheus and Jaeger — are installed here.
There is no Grafana; the reason is recorded in
[specification changes](../specifications.md#readings-and-additions).

**Verify:** the UI answers, Prometheus is scraping the collector, and a trace from a demonstrator
journey is retrievable in Jaeger end to end.

## Teardown

Teardown follows the same rule as the zones: `helm uninstall`, then confirm that no namespace, CRD
or secret survives. The runner registration is removed separately and deliberately, because an
orphaned self-hosted runner holding key material is the worst thing this cluster can leave behind.

## Operations

- **The pipeline is the record.** Every image that reaches a zone was built here, signed by digest
  here, and has an SBOM and a mock attestation published alongside it.
- **Nothing is built on a developer machine.** A build that cannot be reproduced by this runner is
  not a release candidate.
- **Key material never leaves the runner**, is never printed into a log, and is never baked into an
  image layer.
