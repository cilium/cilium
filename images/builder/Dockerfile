# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG UBUNTU_IMAGE=docker.io/library/ubuntu:26.04@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b
ARG TESTER_IMAGE=quay.io/cilium/image-tester:1787138071-3b8cd9a@sha256:d460f28d759ec06f5e7fbc9a91ef7f556d84f6e763f8b78ca128907455ffbc7c
ARG GOLANG_IMAGE=docker.io/library/golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:19.1.7-1785833026-d8383c5@sha256:80ae6ceb1a1556d5f65f7a086d873c4706ed548444c4d49d89cbeedf24f817d4

FROM ${GOLANG_IMAGE} AS golang-dist

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist

FROM ${UBUNTU_IMAGE} AS rootfs

# Change the number to force the generation of a new git-tree SHA. Useful when
# we want to re-run 'apt-get upgrade' for stale images.
ENV FORCE_BUILD=1

# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
RUN \
    export DEBIAN_FRONTEND=noninteractive && \
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
    ca-certificates \
    coreutils \
    curl \
    gcc \
    git \
    libc6-dev \
    make \
    ccache \
    python3-scapy \
    python3-jinja2 && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=golang-dist /usr/local/go /usr/local/go
RUN mkdir -p /go
ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH="${GOROOT}/bin:${GOPATH}/bin:${PATH}"

RUN GOARCH=${TARGETARCH} CGO_ENABLED=0 go install github.com/go-delve/delve/cmd/dlv@latest

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

WORKDIR /go/src/github.com/cilium/cilium/images/builder
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    ./install-test-formatters.sh

# clang compiles the BPF datapath in the builder (e.g. 'make -C bpf build_all',
# 'make run_bpf_tests')
# llvm-objcopy/llvm-strip are used by the BPF Go tests (pkg/bpf/testdata).
# llc is intentionally not copied: the BPF build is clang-only, and the datapath
# verifier tests extract the toolchain from the cilium-llvm image (see
# contrib/scripts/extract-llvm.sh), not from this image.
COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llvm-objcopy /usr/local/bin/llvm-strip /bin/

# Create a cache directory with 777 so that we can run the builder image and
# compile golang code from any UID.
RUN mkdir -p /.cache && chmod 777 /.cache && \
    mkdir -p /go/bin && chmod 777 /go/bin

FROM ${TESTER_IMAGE} AS test
COPY --from=rootfs / /
COPY test /test
RUN /test/bin/cst

# this image is large, and re-using layers is beneficial,
# so final images is not squashed
FROM rootfs AS release
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium
