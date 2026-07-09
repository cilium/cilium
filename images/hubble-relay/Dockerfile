# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# distroless images are signed by cosign and can be verified using:
# $ cosign verify $IMAGE_NAME --certificate-oidc-issuer https://accounts.google.com --certificate-identity keyless@distroless.iam.gserviceaccount.com
ARG BASE_IMAGE=gcr.io/distroless/static:nonroot@sha256:d29e660cc75a5b6b1334e03c5c81ccf9bc0884a002c6000dbf0fb96034814478
ARG GOLANG_IMAGE=docker.io/library/golang:1.25.12@sha256:b81f36974c3984520a04756fbfd901f98c283d5c1eb3a905b52ce431afa16727
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:3c4dd956dfb33c60e5b03cb81315ffef534c48bc@sha256:54de07f9d076bb32373443c4fffc8badf1f6a68e487602b455730b60e103a4ce

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} AS builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
# MODIFIERS are extra arguments to be passed to make at build time.
ARG MODIFIERS

WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${TARGETARCH} DESTDIR=/out/${TARGETOS}/${TARGETARCH} $(echo $MODIFIERS | tr -d '"') \
    build-container-hubble-relay install-container-binary-hubble-relay

WORKDIR /go/src/github.com/cilium/cilium
# licenses-all is a "script" that executes "go run" so its ARCH should be set
# to the same ARCH specified in the base image of this Docker stage (BUILDARCH)
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${BUILDARCH} licenses-all && mv LICENSE.all /out/${TARGETOS}/${TARGETARCH}

FROM ${GOLANG_IMAGE} AS gops

WORKDIR /go/src/github.com/cilium/cilium/images/runtime
ARG TARGETARCH
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    ./build-gops.sh

FROM ${BASE_IMAGE} AS release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
COPY --from=gops /out /
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/hubble-relay /usr/bin/hubble-relay
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/LICENSE.all /LICENSE.all
# Configure gops to use a temporary directory, to prevent permission
# issues depending on the UID configured to run the entrypoint.
COPY --chmod=777 --from=scratch / /home/gops
ENV GOPS_CONFIG_DIR=/home/gops
# use uid:gid for the nonroot user for compatibility with runAsNonRoot
USER 65532:65532
ENTRYPOINT ["/usr/bin/hubble-relay"]
CMD ["serve"]
