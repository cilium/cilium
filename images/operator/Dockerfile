# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE=scratch
ARG GOLANG_IMAGE=docker.io/library/golang:1.21.12@sha256:5f75ec90bd47df95179adb7d5053a72872cf952e6bc375ee73683792068a6383
ARG ALPINE_IMAGE=docker.io/library/alpine:3.18.8@sha256:5292533eb4efd4b5cf35e93b5a2b7d0e07ea193224c49446c7802c19ee4f2da5
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:6d5abd248cca6e7c5f34d261e91eb23aef0b005b@sha256:7bb661bc32b61aa7c23e55bd0ec7817647dbe923200369f0e3934c86bceb5e4e

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
ARG OPERATOR_VARIANT

WORKDIR /go/src/github.com/cilium/cilium

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${TARGETARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} NOOPT=${NOOPT} LOCKDEBUG=${LOCKDEBUG} \
    DESTDIR=/out/${TARGETOS}/${TARGETARCH} build-container-${OPERATOR_VARIANT} install-container-binary-${OPERATOR_VARIANT}

# licenses-all is a "script" that executes "go run" so its ARCH should be set
# to the same ARCH specified in the base image of this Docker stage (BUILDARCH)
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${BUILDARCH} licenses-all && mv LICENSE.all /out/${TARGETOS}/${TARGETARCH}

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${ALPINE_IMAGE} as certs
RUN apk --update add ca-certificates

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as gops

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    ./build-gops.sh

FROM ${BASE_IMAGE} as release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG OPERATOR_VARIANT
LABEL maintainer="maintainer@cilium.io"
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=gops /out/${TARGETOS}/${TARGETARCH}/bin/gops /bin/gops
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/cilium-${OPERATOR_VARIANT} /usr/bin/cilium-${OPERATOR_VARIANT}
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/LICENSE.all /LICENSE.all
WORKDIR /
ENV GOPS_CONFIG_DIR=/
CMD ["/usr/bin/cilium-${OPERATOR_VARIANT}"]

FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} as debug-tools

#
# Cilium Operator debug image.
#
# Typical image bulids will stop above at the 'release' target, but
# developers follow this Dockerfile to the end. Starting from a release
# image, install delve debugger and wrap the cilium-operator binary calls
# with a script that automatically provisions the debugger on a
# dedicated port.
FROM release as debug
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG OPERATOR_VARIANT
ARG DEBUG_HOLD
ENV DEBUG_PORT=2346
ENV DEBUG_HOLD=${DEBUG_HOLD}
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/cilium-${OPERATOR_VARIANT} /usr/bin/cilium-${OPERATOR_VARIANT}-bin
COPY --from=debug-tools /go/bin/dlv /usr/bin/dlv
COPY --from=debug-tools /out/${TARGETOS}/${TARGETARCH}/bin/debug-wrapper /usr/bin/cilium-${OPERATOR_VARIANT}
