# Zone values files

One file per zone, created at stand-up from what the cluster baseline recorded, and
passed to every install of the zone:

```bash
helm upgrade --install ztd deployment/helm/ztd -n ztd-system --create-namespace \
  -f deployment/helm/ztd/zones/<zone>.yaml --wait
```

The chart has no defaults for the zone record on purpose. `zone.kubernetesVersion`,
`zone.storageClass` and `zone.loadBalancer.type` are facts about the cluster, and the chart
refuses to render until the file states them, so a zone is never installed on assumed values.
`zone-a.example.yaml` shows the shape; the local kind cluster uses `../ci/values.yaml`.

A zone file records a cluster; it does not mean the chart is installed there. `ionos.yaml` is
recorded from the IONOS cluster and validated against its API with a server-side dry run, but the
chart is not installed on that cluster (see the file's header). The files for zone A and zone B are
added when the OSC clusters are provided.
