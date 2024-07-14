# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=quay.io/cilium/image-compilers:5569a29cea6b3ad50aeb03102aaf3dc03841197c@sha256:b15dbedb7c49816c74a765e2f6ecdb9359763b8e4e4328d794f48b9cefae9804
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:c1d217bb9fa7bfdaa1fd277999f50fe562f7fae5@sha256:9501d73f44ba19b8d7033e4ba2c8ad19e46591f34697aef36918bc2c94acb824
ARG TESTER_IMAGE=quay.io/cilium/image-tester:dd09c8d3ef349a909fbcdc99279516baef153f22@sha256:c056d064cb47c97acd607343db5457e1d49d9338d6d8a87e93e23cc93f052c73
ARG GOLANG_IMAGE=docker.io/library/golang:1.22.5@sha256:829eff99a4b2abffe68f6a3847337bf6455d69d17e49ec1a97dac78834754bd6
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:9f1bfe736009afb1fbb562718bbc42ea07d37d8e@sha256:a666a7a01a2dc610c3ab6e32f25ca5e294201f3cbbc01f233320c527955deee3

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
    apt-get install -y --no-install-recommends \
      # Install cross tools for both arm64 on amd64
      gcc-aarch64-linux-gnu \
      g++-aarch64-linux-gnu \
      libc6-dev-arm64-cross \
      binutils-aarch64-linux-gnu \
      gcc-x86-64-linux-gnu \
      g++-x86-64-linux-gnu \
      libc6-dev-amd64-cross \
      binutils-x86-64-linux-gnu \
      # Dependencies to unzip protoc
      unzip \
      # Base Cilium-build dependencies
      binutils \
      coreutils \
      curl \
      gcc \
      git \
      libc6-dev \
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

RUN CGO_ENABLED=0 go install github.com/go-delve/delve/cmd/dlv@latest

WORKDIR /go/src/github.com/cilium/cilium/images/builder
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    ./install-gitconfig.sh

WORKDIR /go/src/github.com/cilium/cilium/images/builder
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    ./build-debug-wrapper.sh

WORKDIR /go/src/github.com/cilium/cilium/images/builder
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    ./install-protoc.sh

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    ./install-protoplugins.sh

# used to facilitate the verifier tests
COPY --from=llvm-dist /usr/local/bin/llvm-objcopy /bin/

# Create a cache directory with 777 so that we can run the builder image and
# compile golang code from any UID.
RUN mkdir -p /.cache && chmod 777 /.cache && \
    mkdir -p /go/bin && chmod 777 /go/bin

FROM ${TESTER_IMAGE} as test
COPY --from=rootfs / /
COPY test /test
RUN /test/bin/cst

# this image is large, and re-using layers is beneficial,
# so final images is not squashed
FROM rootfs as release
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium
