# CI/CD

Continuous integration for this repository **references the shared Eclipse XFSC workflows** in
[`eclipse-xfsc/dev-ops`](https://github.com/eclipse-xfsc/dev-ops/tree/main/.github/workflows)
rather than copying them. Keeping the bodies upstream is what the Technical Development
Requirements ask for, and it means a fix to a shared workflow reaches this repository without a
pull request here.

## Workflows in this repository

| Workflow | Triggers | What it does |
|---|---|---|
| `.github/workflows/eclipse-dash.yml` | schedule, release, manual | Calls the shared Eclipse Dash licence scanner and files IP review requests for dependencies |
| `.github/workflows/sbom.yml` | schedule, release, manual | Calls the shared SBOM generator |
| `.github/workflows/docs.yml` | push to `main` affecting `docs/`, manual | Builds the MkDocs site and publishes it to the `gh-pages` branch |

## Licence scanning

Every third-party dependency must clear Eclipse Dash before it ships. The scan runs on a schedule
and on release today; it becomes a **blocking pull-request gate** once the Go module exists, since
the shared Go scanner reads `go.sum` and has nothing to scan before then.

Dependencies that Dash cannot clear automatically go to the Eclipse IP team for review. A dependency
under a licence that the project cannot accept is replaced, not waived.

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
