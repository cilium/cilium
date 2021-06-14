# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=quay.io/cilium/image-compilers:6ed96e618f68cd941b62b546fc8d161db0144d84@sha256:5245610a830b14972d5b287fc0318ac6ab0d420e4afc9b5db9032a04fd706d32
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:13fc53394a676909ee74fbde1ba9de485e01bd34@sha256:95a5bd7b5bc73b1cbdf9a3704cb3389ca1857e283ae38941539214cbae7c6dcd
ARG TESTER_IMAGE=quay.io/cilium/image-tester:eb76f0d4d585946bb0267b4c4478cceed17bbd87@sha256:c9a598cdc4843e62ab4e430f36343ca06d5292506261f17e466e0f1cbb48ddbb
ARG GOLANG_IMAGE=docker.io/library/golang:1.16.5@sha256:360bc82ac2b24e9ab6e5867eebac780920b92175bb2e9e1952dce15571699baa
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:0147a23fdada32bd51b4f313c645bcb5fbe188d6@sha256:24fd3ad32471d0e45844c856c38f1b2d4ac8bd0a2d4edf64cffaaa3fd0b21202

FROM ${COMPILERS_IMAGE} as compilers-image

FROM ${GOLANG_IMAGE} as golang-dist

FROM ${CILIUM_LLVM_IMAGE} as llvm-dist

FROM ${CILIUM_RUNTIME_IMAGE} as rootfs

# Change the number to force the generation of a new git-tree SHA. Useful when
# we want to re-run 'apt-get upgrade' for stale images.
ENV FORCE_BUILD=1

# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
RUN \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    # Only install cross tools on amd64
    CROSSPKG="" && [ "$TARGETARCH" != "amd64" ] || CROSSPKG="gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross binutils-aarch64-linux-gnu" && \
    apt-get install -y --no-install-recommends \
      $CROSSPKG \
      # Dependencies to unzip protoc
      unzip \
      # Base Cilium-build dependencies
      binutils \
      coreutils \
      curl \
      gcc \
      git \
      libc6-dev \
      libelf-dev \
      make && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=compilers-image /usr/lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu

COPY --from=golang-dist /usr/local/go /usr/local/go
RUN mkdir -p /go
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "${GOROOT}/bin:${GOPATH}/bin:${PATH}"

WORKDIR /go/src/github.com/cilium/cilium/images/builder
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    ./build-go-deps.sh

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    ./install-protoc.sh

# used to facilitate the verifier tests
COPY --from=llvm-dist /usr/local/bin/llvm-objcopy /bin/

FROM ${TESTER_IMAGE} as test
COPY --from=rootfs / /
COPY test /test
RUN /test/bin/cst

# this image is large, and re-using layers is beneficial,
# so final images is not squashed
FROM rootfs
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium
