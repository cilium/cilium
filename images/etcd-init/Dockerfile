# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE=scratch
ARG GOLANG_IMAGE=docker.io/library/golang:1.20.4@sha256:690e4135bf2a4571a572bfd5ddfa806b1cb9c3dea0446ebadaf32bc2ea09d4f9
ARG ALPINE_IMAGE=docker.io/library/alpine:3.18.0@sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:897005980f57d7eb1e2819744be5e3c7c1a759c5@sha256:995c1ddcc70c1793265776e571785ea16c4d805516792e477e7a0460c8dbd16a

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

WORKDIR /go/src/github.com/cilium/cilium/etcd-init

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${TARGETARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} NOOPT=${NOOPT} LOCKDEBUG=${LOCKDEBUG} etcd-init \
    && mkdir -p /out/${TARGETOS}/${TARGETARCH}/usr/bin && mv etcd-init /out/${TARGETOS}/${TARGETARCH}/usr/bin

WORKDIR /go/src/github.com/cilium/cilium
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
LABEL maintainer="maintainer@cilium.io"
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=gops /out/${TARGETOS}/${TARGETARCH}/bin/gops /bin/gops
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/etcd-init /usr/bin/etcd-init
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/LICENSE.all /LICENSE.all
WORKDIR /
ENV GOPS_CONFIG_DIR=/
ENTRYPOINT ["/usr/bin/etcd-init"]
CMD ["init"]

