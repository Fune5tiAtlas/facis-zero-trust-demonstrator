# Container builds

Build contexts and Dockerfiles for the services in `services/`.

Images are built by CI, signed by digest, and admitted to a cluster only if that signature and the
accompanying attestations verify. Images are never built or pushed by hand.
