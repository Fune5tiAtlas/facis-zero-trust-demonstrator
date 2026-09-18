# CI/CD

Continuous integration for this repository **references the shared Eclipse XFSC workflows** in
[`eclipse-xfsc/dev-ops`](https://github.com/eclipse-xfsc/dev-ops/tree/main/.github/workflows)
rather than copying them. Keeping the bodies upstream is what the Technical Development
Requirements ask for, and it means a fix to a shared workflow reaches this repository without a
pull request here.

## Workflows in this repository

| Workflow | Triggers | What it does |
|---|---|---|
| `.github/workflows/eclipse-dash.yml` | every pull request, schedule, release, manual | Calls the shared Eclipse Dash licence scanner and files IP review requests for dependencies |
| `.github/workflows/sbom.yml` | schedule, release, manual | Calls the shared SBOM generator |
| `.github/workflows/docs.yml` | push to `main` affecting `docs/`, manual | Builds the MkDocs site and publishes it to the `gh-pages` branch |
| `.github/workflows/workflow-hygiene.yml` | every pull request, manual | Fails the pull request when an action is not pinned to a commit or a token scope is too wide |
| `.github/workflows/ci.yml` | every pull request, push to `main`, manual | Go lint and tests, image build with the Linux assertion and a Trivy scan, chart lint and dry-run render |

## The service pipeline

`ci.yml` is one pipeline shape that every service in the monorepo reuses, so quality is consistent
and nobody hand-rolls their own:

| Job | What it does | Blocking |
|---|---|---|
| `Go tests` | Calls the shared `go-test.yml`, which runs the tests of every Go module it finds | yes |
| `Go lint` | `golangci-lint run ./...` | yes |
| `Image build and scan` | Builds each context under `deployment/docker/` for `linux/amd64`, asserts the built image's OS, then scans it with Trivy for HIGH and CRITICAL vulnerabilities | yes |
| `Chart lint and render` | `helm lint` and a `helm template` dry-run render of every chart under `deployment/helm/` | yes |

ZT-13 requires Linux images. The pipeline reads the OS back off the built image with
`docker image inspect` and fails if it is anything but `linux/amd64`, rather than trusting the
Dockerfile to be right. The platform it read is printed in the job output either way.

Each job passes quietly while the thing it checks does not exist yet — no Go module, no build
context, no chart — so the pipeline is green on an empty skeleton and starts enforcing the moment
the first service lands.

### Go module layout

The demonstrator is **one Go module at the repository root**, with each service a package under
`services/` and shared code in `internal/`. This is not a style preference: the Eclipse Dash
scanner and the shared SBOM generator both read the root `go.sum`, and a module per service would
leave the licence gate and the release SBOM with nothing to read.

`go.mod` declares **Go 1.24**, matching the `golang:1.24.x` containers the shared org workflows run
in. A newer toolchain directive would break them.

## Repository protection and least privilege

The demonstrator applies its own zero-trust posture to the delivery machine (ZT-56): nothing reaches
`main` unreviewed, and no pipeline holds a credential wider than the job in front of it needs.

### Branch protection

`main` is protected by a ruleset an organisation administrator applies — it is an Eclipse XFSC
organisation setting and cannot be declared from this repository's tree. The required ruleset:

| Rule | Setting |
|---|---|
| Direct pushes to `main` | Blocked; changes arrive by pull request |
| Approving reviews | At least one, from someone other than the author |
| Stale approvals | Dismissed when new commits are pushed |
| Required status checks | `Workflow hygiene`, `Licence gate`, `Go lint`, `Image build and scan`, `Chart lint and render` |
| Force pushes and branch deletion | Blocked |
| Enforcement | Applies to administrators |

### Token scopes

The repository's default workflow token is read-only — an administrator setting applied alongside the
ruleset above. Every workflow then declares its own top-level `permissions:` block rather than
relying on that default, and a job that needs more than read access grants it at the job level with
a comment naming the reason: `docs.yml` writes to `gh-pages`, `sbom.yml` uploads the SBOM onto a
release. Wildcard scopes (`write-all`) are never used.

### Action pinning

Third-party actions are referenced by full commit SHA with the version in a trailing comment, so a
moved tag cannot change what runs in the pipeline:

```yaml
uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
```

The shared `eclipse-xfsc/dev-ops` workflows stay on `@main` on purpose: the Technical Development
Requirements ask for the shared bodies to be referenced rather than copied, and pinning them would
stop fixes reaching this repository. The residual risk is accepted for workflows inside the
project's own organisation and does not extend to anything outside it. Dependabot proposes the SHA
bumps weekly.

`scripts/check-workflow-hygiene.sh` enforces all three rules — pinning, a declared permissions block,
and no wildcard write scope — on every pull request. Run it locally before pushing:

```bash
scripts/check-workflow-hygiene.sh
```

## Licence scanning

Every third-party dependency must clear Eclipse Dash before it ships. The scan is a **blocking
pull-request gate**: a dependency Dash marks `restricted` fails the `Licence gate` job and the
merge is refused.

The shared Go scanner reads `go.sum`, so the gate skips itself while no Go module exists — a
preceding job looks for the file and the scan runs only when it is there. The workflow itself is
not filtered by path, so the required check is always reported: a skipped job counts as passing,
whereas a workflow that never starts leaves the pull request waiting forever.

Dependencies that Dash cannot clear automatically go to the Eclipse IP team for review. A dependency
under a licence that the project cannot accept is replaced, not waived — and where the requirements
prescribe the component and leave no alternative, it goes to the client as a written licence
exception before it is merged. The process and the OpenBao worked example are in
[OSS dependencies](dependencies.md#licence-exceptions).

## Documentation publication

`docs.yml` builds the MkDocs site and pushes it to the `gh-pages` branch. GitHub Pages must be
enabled on the repository with its source set to that branch — a one-time repository setting a
maintainer applies.

## Adding a workflow

Reference the shared workflow rather than reimplementing it:

```yaml
jobs:
  call-remote-workflow:
    secrets: inherit
    uses: eclipse-xfsc/dev-ops/.github/workflows/<workflow>.yml@main
```
