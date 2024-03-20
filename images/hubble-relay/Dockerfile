# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# distroless images are signed by cosign. You should verify the image with the following public key:
# $ cat cosign.pub
# -----BEGIN PUBLIC KEY-----
# MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWZzVzkb8A+DbgDpaJId/bOmV8n7Q
# OqxYbK0Iro6GzSmOzxkn+N2AKawLyXi84WSwJQBK//psATakCgAQKkNTAA==
# -----END PUBLIC KEY-----
# $ cosign verify --key cosign.pub $BASE_IMAGE
# The key may be found at the following address:
# https://raw.githubusercontent.com/GoogleContainerTools/distroless/main/cosign.pub
ARG BASE_IMAGE=gcr.io/distroless/static-debian11:nonroot@sha256:55c636171053dbc8ae07a280023bd787d2921f10e569f3e319f1539076dbba11
ARG GOLANG_IMAGE=docker.io/library/golang:1.22.1@sha256:0b55ab82ac2a54a6f8f85ec8b943b9e470c39e32c109b766bbc1b801f3fa8d3b
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:bd61a0f0d0887d5836d8ec6e770672742a2b01a9@sha256:26042a41693ca6d978b3b013a5656c55f51a4e7691262f77f175542b8c0e73e2

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG NOSTRIP
ARG NOOPT
ARG LOCKDEBUG
ARG RACE

WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    make GOARCH=${TARGETARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} NOOPT=${NOOPT} LOCKDEBUG=${LOCKDEBUG} \
    DESTDIR=/out/${TARGETOS}/${TARGETARCH} build-container-hubble-relay install-container-binary-hubble-relay

WORKDIR /go/src/github.com/cilium/cilium
# licenses-all is a "script" that executes "go run" so its ARCH should be set
# to the same ARCH specified in the base image of this Docker stage (BUILDARCH)
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    make GOARCH=${BUILDARCH} licenses-all && mv LICENSE.all /out/${TARGETOS}/${TARGETARCH}

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as gops

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    ./build-gops.sh

#
# gRPC health probes
#
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} as grpc_health_probe
ARG BUILDPLATFORM
COPY images/hubble-relay/download-grpc-health-probe.sh /tmp/download-grpc-health-probe.sh
RUN /tmp/download-grpc-health-probe.sh

FROM ${BASE_IMAGE} as release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
COPY --from=gops /out/${TARGETOS}/${TARGETARCH}/bin/gops /bin/gops
COPY --from=grpc_health_probe /out/${TARGETOS}/${TARGETARCH}/bin/grpc_health_probe /bin/grpc_health_probe
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/hubble-relay /usr/bin/hubble-relay
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/LICENSE.all /LICENSE.all
# use uid:gid for the nonroot user for compatibility with runAsNonRoot
USER 65532:65532
ENTRYPOINT ["/usr/bin/hubble-relay"]
CMD ["serve"]
