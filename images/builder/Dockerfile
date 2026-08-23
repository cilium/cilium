# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=quay.io/cilium/image-compilers:1785833026-d8383c5@sha256:528cddfe9b55fff1e825f1014fbcd67231a4955e96fdf06bc0051354419b3824
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:411cda02fea19b6db77192de21d1c0fa9132c1ae@sha256:d4f786b9dc23cc4e107f8f4c93970e6c46603cc792d850a242e3f0ade295be08
ARG TESTER_IMAGE=quay.io/cilium/image-tester:1787138071-3b8cd9a@sha256:d460f28d759ec06f5e7fbc9a91ef7f556d84f6e763f8b78ca128907455ffbc7c
ARG GOLANG_IMAGE=docker.io/library/golang:1.25.13@sha256:cbff9d1a9041b316010f2da6b701b6c0d597718cb90928c85eb597334a0d23d4
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:19.1.7-1785833026-d8383c5@sha256:80ae6ceb1a1556d5f65f7a086d873c4706ed548444c4d49d89cbeedf24f817d4

FROM ${COMPILERS_IMAGE} AS compilers-image

FROM ${GOLANG_IMAGE} AS golang-dist

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist

FROM ${CILIUM_RUNTIME_IMAGE} AS rootfs

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
    make \
    ccache \
    python3-scapy \
    python3-jinja2 && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=compilers-image /usr/lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu

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

# used to facilitate the verifier tests
COPY --from=llvm-dist /usr/local/bin/llvm-objcopy /usr/local/bin/llvm-strip /bin/

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
