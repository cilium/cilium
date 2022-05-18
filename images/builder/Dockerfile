# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=quay.io/cilium/image-compilers:e847f4176cb42ae27fa459a10df6721c43702b64@sha256:78df068553627c53d8dbe0f61275271b597c55c60585f3ea9f6916bd3cfd611a
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:ff7a10130f9bb0922e613fdab73280f78dab1957@sha256:c315cca97ad1e50cb0c4026f79a41fa89abf17bbd428f7bbf08c74967cf0bbbf
ARG TESTER_IMAGE=quay.io/cilium/image-tester:c37f768323abfba87c90cd9c82d37136183457bc@sha256:4c9d640b6379eb4964b8590acc95ca2dfaa71df70f4467fb7d8ac076acf6a8e1
ARG GOLANG_IMAGE=docker.io/library/golang:1.16.15@sha256:995b095588ef5e635aec9bdc97cd2a40f29ddec0525461eeba062a9487e82bcd
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:86ec4491b398563f8060286160a463f981366d61@sha256:75bc3d9865851f9a37749a6ef185c1d2fb02fc30d2e5578bb9261fd1c1a2c1f7

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
