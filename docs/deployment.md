# Deployment and teardown

> **Status:** structure established. Commands are added as the umbrella chart lands.

## Preconditions

- Kubernetes **1.29 or later** on each target cluster.
- A CNI that supports the mesh baseline recorded in
  [ADR-0001](adr/0001-service-mesh-mode-istio-ambient-with-cilium.md).
- A container registry reachable from the clusters, with credentials available to the cluster.
- DNS delegation for the trust zone.

## Installing a zone

The demonstrator installs as a single umbrella Helm chart per zone. The chart separates the
management and data planes into distinct namespaces and orders installation so that workload
identity exists before any workload starts.

```bash
# placeholder — the umbrella chart lands with the platform work
helm install ztd deployment/helm/ztd -n ztd-mgmt --create-namespace -f <values file>
```

## Teardown

```bash
helm uninstall ztd -n ztd-mgmt
```

Teardown must leave no orphaned namespaces, CRDs or secrets; this is verified by an acceptance
scenario rather than by inspection.

## Reproducibility

Every environment is reproducible from this repository plus its values files. Nothing is configured
by hand on a cluster — if a step cannot be expressed in the chart or a script, that is a defect
rather than a documentation gap.
