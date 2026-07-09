# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=quay.io/cilium/image-compilers:1782994507-725357c@sha256:004fa5966bba637f748bc7fa129ad61500b43410177f11f590a75b29431279de
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:9fb4b62767149e8cd391f9341f166b6fe03423fa@sha256:2b7598259ecd021662106e03dc11aca4e437d81732b565b9e1dee2792b2efcd8
ARG TESTER_IMAGE=quay.io/cilium/image-tester:1782916218-36ae25f@sha256:238a8309872dc1905bf559f6a7ed5101775aa38ed920cf992184af557b1e5f53
ARG GOLANG_IMAGE=docker.io/library/golang:1.26.5@sha256:63f132d58c1f589f0dcda584933a9bb44bfda1150f1506377f5a902f34d86033
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:19.1.7-1782898005-bed4da5@sha256:270bf0e70853c388b72c2247e4ade91d35d74898e2ec12edd5b72ace9ee34333

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
