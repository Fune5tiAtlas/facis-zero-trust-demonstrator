# Application service source verification

Date: 9 October 2026. Baseline: the downloaded `pr/22` archive whose embedded commit is `852cc91d7fc2c6dab97c06f5d9d969298ca42812`, plus the Participant and Protected Resource additions in this handoff. There is no service delivery commit yet.

Environment: Windows/amd64, Go 1.27.2, Node.js v24.19.0. The service code uses the repository module unchanged. Local processes bound to loopback on temporary ports; Participant used `http-sample`, Resource used `sample`, both deadlines were 5 seconds and the Resource slow delay was 2 seconds.

| Check | Result |
| --- | --- |
| `gofmt` on both service packages and entry points | PASS; formatting normalized |
| `go build -buildvcs=false ./cmd/participant ./cmd/protected-resource` | PASS |
| `go test ./services/participant/... ./services/protectedresource/... -v -timeout 30s` | PASS, both packages |
| `go vet ./services/participant/... ./services/protectedresource/...` | PASS |
| Separate Windows executable builds for both entry points | PASS |
| Separate `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` builds for both entry points | PASS; cross-compilation only |
| `node scripts/smoke-application-services.mjs` against both running local processes | PASS, 12 checks |
| Container builds, image scan, signing and registry publication | NOT RUN; Dockerfiles received 10 October |
| Shared OSC deployment, ingress and ORCE runtime integration | NOT RUN |
| Repository-wide CI / Linux execution / final two-zone acceptance | NOT RUN |

The HTTP checks cover both health endpoints plus success, denied, unavailable, error and slow scenarios directly on Resource and through Participant. They check status mappings, request/correlation IDs, sample markers, reason codes, timestamps and safe-data shape. The HTTP adapter returned Resource's reason codes; this was a real local process-to-process HTTP call carrying sample outcomes, not Participant's in-process sample adapter.

The Linux executable builds do not prove container behavior. The HTTP results do not prove authorization, credential revocation, scope enforcement, attestation or any final ZT acceptance row. Rerun the checks on the final PR revision after adding the container recipes; attach CI/runtime evidence separately.

## Dockerfile receipt and checks — 10 October 2026

Both supplied Dockerfiles are now included unchanged. Static review confirms the service entry points and ports, repository-root COPY paths, non-root UID/GID 65532, CA certificate copy, SIGTERM and executable entry points. The Participant image selects http-sample and requires its Resource base URL at runtime.

The pinned builder index `golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d` was resolved using `docker buildx imagetools inspect`; it includes Linux/amd64. This verifies registry metadata, not image-layer contents or a successful build.

Both Go build commands passed with the Dockerfiles' `-mod=readonly -trimpath -buildvcs=false -ldflags="-s -w"` flags, compiling for Linux/amd64 from isolated directories containing only each Dockerfile's COPY inputs. These used the portable Go toolchain on Windows, not the builder container. Image build/scan, runtime container checks, signing/publication and deployment still require the ATLAS pipeline.
