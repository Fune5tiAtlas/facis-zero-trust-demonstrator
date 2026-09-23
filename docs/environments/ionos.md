# IONOS Cloud — CI/CD and visualization

The third cluster. It is meant to run the delivery machinery and the visualization surface, and
holds no demonstration workload: nothing that participates in a zone-to-zone call runs here, so a
failure in the pipeline cannot be mistaken for a failure in the demonstrator.

!!! note "Status"
    The cluster was provided on 23 September 2026. What is installed today is ORCE, the BDD pool and
    nothing else; stages 1 to 5 below describe that state and were checked against the cluster,
    except where a stage says otherwise. The runner, registry access and visualization stages are
    planned and marked so.

## Before you start

You need:

- a kubeconfig for the IONOS cluster with rights to create namespaces, cluster roles and bindings
  (kept outside the repository, never committed);
- Docker with `linux/amd64` support, Helm v4.3.0 and kubectl;
- Node.js 22 and `npm ci` in this repository, for the acceptance run;
- this repository checked out.

```bash
export KUBECONFIG=/path/to/ionos-admin.kubeconfig
kubectl version -o json | jq -r '.serverVersion.gitVersion'
```

**Verify:** the server reports v1.29 or later (v1.35.6 at the time of writing).

## 1. The cluster as provided

IONOS Managed Kubernetes, one node pool. The provider installs and operates the CNI (Calico), the
IONOS CSI driver with its storage classes, CoreDNS and its own policy validator; none of them is
replaced.

```bash
kubectl get nodes -o wide
kubectl -n kube-system get daemonset calico-node csi-ionoscloud
kubectl get storageclass
```

**Verify:** every node is `Ready`, and both daemonsets report as many ready pods as desired.

The common baseline ([Environments](index.md)) names Cilium with `cni.exclusive=false`, for the
service mesh ([ADR-0001](../adr/0001-service-mesh-mode-istio-ambient-with-cilium.md)). This cluster
runs no mesh and no demonstration workload, so its provider CNI is kept; whether the visualization
stage needs the mesh here is decided with that stage.

## 2. The ORCE image

ORCE runs the first-party image built from `deployment/docker/orce` (see
[Packaging](../packaging.md)): upstream ORCE with Helm and kubectl pinned, the lifecycle Builder
Node and flow, credentials from the environment, JSON logging, non-root. It is `linux/amd64` only.
The pipeline builds and scans it on every pull request; to build it by hand:

```bash
docker build --platform linux/amd64 -f deployment/docker/orce/Dockerfile -t "$REGISTRY/facis-ztd-orce:$(git rev-parse --short HEAD)" .
docker push "$REGISTRY/facis-ztd-orce:$(git rev-parse --short HEAD)"
```

**Verify:** the push prints the image digest. Everything below references the image by that
digest (`IMAGE=<registry>/facis-ztd-orce@sha256:…`), never by tag.

## 3. ORCE

Installed from the interim manifests in `deployment/orce-minimal/` (see its README) until the ORCE
chart exists (FZTD-187).

```bash
kubectl apply -f deployment/orce-minimal/base.yaml

# Credentials: generate them, store only bcrypt hashes (and the read token) in the cluster, and
# keep the plaintext in the team's password manager (see below).
hash() { docker run --rm --platform linux/amd64 --entrypoint node "$IMAGE" \
  -e "console.log(require('/opt/maestro/MBE/node_modules/bcryptjs').hashSync(process.argv[1], 10))" "$1"; }
admin_pass=$(openssl rand -hex 16); http_pass=$(openssl rand -hex 16); read_token=$(openssl rand -hex 32)
kubectl -n ztd-orce create secret generic orce-credentials \
  --from-literal=ORCE_ADMIN_USER=admin --from-literal=ORCE_ADMIN_PASSWORD_HASH="$(hash "$admin_pass")" \
  --from-literal=ORCE_HTTP_USER=bdd --from-literal=ORCE_HTTP_PASSWORD_HASH="$(hash "$http_pass")" \
  --from-literal=ORCE_READ_TOKEN="$read_token"

sed "s|__IMAGE__|$IMAGE|" deployment/orce-minimal/orce.yaml | kubectl apply -f -
```

Before closing the shell, copy `$admin_pass`, `$http_pass` and `$read_token` into the password
manager one at a time through the clipboard (for example `printf %s "$admin_pass" | pbcopy` on
macOS), rather than echoing them to the terminal; they exist nowhere else.

**Verify:**

```bash
kubectl -n ztd-orce rollout status deployment/orce --timeout=5m
kubectl -n ztd-orce get deployment orce -o jsonpath='{.spec.template.spec.containers[0].image}'   # the digest
kubectl -n ztd-orce logs deployment/orce --tail=5          # one JSON object per line
kubectl -n ztd-orce get networkpolicy orce-ingress
```

The rollout completes, the image is the digest you pushed, and the log lines are JSON objects with
`time`, `level`, `type`, `name`, `id` and `msg` ([ORCE logging](../flows.md#orce-logging)); an
image built before JSON logging was added prints prefixed lines instead, and must be replaced. There is
no ingress: ORCE is reached with `kubectl port-forward` until FZTD-187 exposes it over TLS 1.3.

## 4. The BDD pool

The namespaces and least-privilege identities of the cluster acceptance scenarios, bound to ORCE's
ServiceAccount as deployer (the chart's README, `deployment/helm/bdd-pool/README.md`, lists what it
installs):

```bash
helm upgrade --install bdd-pool deployment/helm/bdd-pool --namespace ztd-orce \
  --set deployer.serviceAccount.create=false --set deployer.serviceAccount.name=orce \
  --set observer.serviceAccount.create=false --wait
```

**Verify:**

```bash
kubectl get namespaces -l app.kubernetes.io/name=bdd-pool
kubectl auth can-i create namespaces --as=system:serviceaccount:ztd-orce:orce                          # no
kubectl auth can-i create deployments -n ztd-bdd-tdr-001 --as=system:serviceaccount:ztd-orce:orce      # yes
kubectl auth can-i create deployments -n default --as=system:serviceaccount:ztd-orce:orce              # no
kubectl auth can-i get secrets -n ztd-orce --as=system:serviceaccount:ztd-orce:ztd-bdd-observer        # no
kubectl auth can-i delete pods -n ztd-bdd-tdr-001 --as=system:serviceaccount:ztd-orce:ztd-bdd-observer # no
```

The pool namespaces are listed: `ztd-bdd-tdr-001` … `004`, and `006` for TDR-BDD-06 once the
pool runs this chart version. Each answer is the one in the comment: ORCE deploys only inside the pool, and the observer can neither read ORCE's credentials
nor change anything.

## 5. The acceptance run

The cluster rows (TDR-BDD-01..04 and TDR-BDD-06) run against this cluster with the read-only
observer identity; ORCE does the deploying. In CI this is the `bdd-cluster` job, once
`BDD_CLUSTER_ENABLED` is set and ORCE is reachable from the pipeline ([CI/CD](../ci-cd.md)). By
hand, from an administrator's machine, with the credentials from stage 3:

```bash
# A short-lived observer kubeconfig.
umask 077
kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > ca.crt
kubectl config set-cluster ionos --server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')" \
  --certificate-authority=ca.crt --embed-certs --kubeconfig=observer.kubeconfig
kubectl config set-credentials observer --kubeconfig=observer.kubeconfig \
  --token="$(kubectl -n ztd-orce create token ztd-bdd-observer --duration=12h)"
kubectl config set-context observer --cluster=ionos --user=observer --kubeconfig=observer.kubeconfig
kubectl config use-context observer --kubeconfig=observer.kubeconfig

kubectl -n ztd-orce port-forward service/orce 18801:1880 &

KUBECONFIG=$PWD/observer.kubeconfig BDD_ORCE_URL=http://127.0.0.1:18801 BDD_TARGET=ionos \
BDD_ORCE_ADMIN_TOKEN="$read_token" BDD_ORCE_HTTP_USER=bdd BDD_ORCE_HTTP_PASS="$http_pass" \
BDD_ORCE_LOGS_CMD="kubectl --kubeconfig=$PWD/observer.kubeconfig -n ztd-orce logs deployment/orce --tail=-1" \
npm run bdd:cluster
```

**Verify:** the run reports every scenario passed; every `scenario.json` under
`bundles/bdd/evidence/` carries the cluster's `kube-system` UID
(`kubectl get namespace kube-system -o jsonpath='{.metadata.uid}'`); and every pool namespace is
back to its baseline (`kubectl -n ztd-bdd-tdr-001 get all` shows nothing). Stop the port-forward and
delete `observer.kubeconfig` and `ca.crt` afterwards; the token expires on its own.

## Planned: runner, registry access and visualization

Not installed on this cluster yet. Each gets its stage and its check when it is.

- **Build and signing runner.** The AMD64 Linux runner that builds and signs project images by
  digest, with the key restricted to protected workflows.
- **Registry access.** Pushing images and signatures to the client's registry, and pulling from it
  on the OSC clusters, with a robot account rather than a personal one.
- **Visualization.** The demonstrator UI and the observability interfaces — Prometheus and Jaeger.
  There is no Grafana; the reason is recorded in
  [specification changes](../specifications.md#readings-and-additions).

## Teardown

```bash
kubectl delete -f deployment/orce-minimal/orce.yaml --ignore-not-found
helm uninstall bdd-pool --namespace ztd-orce
kubectl delete -f deployment/orce-minimal/base.yaml --ignore-not-found
```

**Verify:** `kubectl get namespaces | grep ztd-` prints nothing, and
`kubectl get clusterrole,clusterrolebinding | grep ztd-` prints nothing.

## Operations

- **The pipeline is the record.** Every image that reaches a cluster was built by the pipeline and
  is referenced by digest.
- **Credentials never enter the repository.** The administrator kubeconfig, the ORCE credentials
  and the observer tokens live outside it; the cluster stores only hashes and the read token.
- **Key material never leaves the runner**, is never printed into a log, and is never baked into an
  image layer.
