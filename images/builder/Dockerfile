# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=quay.io/cilium/image-compilers:1755973935-c5bf38b@sha256:448b126455a301c48d4189bfa9335f44d7d4524d69dcbc8151013ecb6ac0f042
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:061e77638353be08d1a792ef38b8f4597344139d@sha256:db098a1d65275c3d3f8090706feaab9a30c437fb24942b25ffdea06a010c5bae
ARG TESTER_IMAGE=quay.io/cilium/image-tester:1755531540-60ee83e@sha256:1b05459281d6613acb8573b2cd7f488a0d224eebf031770babbfc6a294501cf7
ARG GOLANG_IMAGE=docker.io/library/golang:1.25.1@sha256:8305f5fa8ea63c7b5bc85bd223ccc62941f852318ebfbd22f53bbd0b358c07e1
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:1755027449-dfe66ec@sha256:6a8632f1772dee0f1f287dd84f4010347c19f350347487603f16210674a3a787

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
