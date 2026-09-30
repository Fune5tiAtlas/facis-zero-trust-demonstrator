# verify-umbrella

Evidence for the umbrella chart (`deployment/helm/ztd`) on the local kind cluster from
`scripts/dev/kind-cilium-up.sh`. `verify.sh` installs the chart from an empty cluster, installs it again to
show nothing changes, reads the layout back, proves with stand-in pods that a data-plane workload
reaches nothing in the management plane except through an allow-matrix lane, switches the mesh
mode to sidecar and back, checks the lint and render guards of the CI chart gate, and tears down without leaving a plane
namespace behind. It writes `evidence.md` next to itself; `evidence.md` in the repository is the
output of the last run.

```bash
scripts/dev/kind-cilium-up.sh
scripts/verify-umbrella/verify.sh
```

`sidecar-values.yaml` is the kind zone in sidecar mode, a fixture of this script only; the chart's
own CI render uses `deployment/helm/ztd/ci/values.yaml`.

The stand-in pods carry only the labels of the allow matrix; nothing else about them is real, and
none of their images is consumed by a zone.
