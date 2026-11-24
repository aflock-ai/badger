# The one image for the model broker and management portal.
#
# The build reaches no network. Third-party modules come from a module-cache image (Dockerfile.gomod
# beside this file), built once where network is allowed and pinned by digest by whoever builds
# this image; GOMOD_IMAGE has no default, so the build fails without it. Integrity does not rest on
# that digest: `go mod verify` recomputes every module's hash from the cache and checks it against
# this repository's go.sum files before anything is compiled, so a missing or altered module fails
# the build. Both bases are pinned by digest; bump them deliberately. Build from testifysec/:
#
#   docker build -f portal/cmd/badger-broker/Dockerfile --build-arg GOMOD_IMAGE=<registry>/badger-gomod@sha256:<digest> -t badger-broker .
ARG GOMOD_IMAGE
FROM ${GOMOD_IMAGE} AS gomod

FROM docker.io/library/golang:1.26-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
COPY --from=gomod /go/pkg/mod /go/pkg/mod
WORKDIR /src
COPY connectors/go.mod ./connectors/
COPY connectors/marking ./connectors/marking
COPY connectors/internal/marking ./connectors/internal/marking
COPY model-broker/go.mod model-broker/go.sum model-broker/*.go model-broker/*.sql model-broker/theme.css ./model-broker/
COPY model-broker/pgdb ./model-broker/pgdb
COPY portal/go.mod portal/go.sum ./portal/
COPY portal/cmd/badger-broker ./portal/cmd/badger-broker
COPY portal/internal ./portal/internal
ENV GOFLAGS=-mod=readonly GOPROXY=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0
WORKDIR /src/model-broker
RUN go mod verify
WORKDIR /src/portal
RUN go mod verify && go build -trimpath -ldflags='-s -w' -o /out/badger-broker ./cmd/badger-broker

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/badger-broker /badger-broker
USER 65532:65532
# internal, edge, provision, admin
EXPOSE 8080 8081 8082 8083
ENTRYPOINT ["/badger-broker"]
CMD ["-config", "/etc/badger-broker/config.json"]
