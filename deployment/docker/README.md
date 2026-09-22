# Container builds

Build contexts and Dockerfiles for the services in `services/`.

Images are built in CI, signed by digest, and admitted only if that signature and the accompanying
attestations verify.
