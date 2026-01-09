# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_IMAGE=docker.io/library/golang:1.25.5@sha256:6cc2338c038bc20f96ab32848da2b5c0641bb9bb5363f2c33e9b7c8838f9a208
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:24.04@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

ARG COMPILERS_IMAGE=quay.io/cilium/image-compilers:1732033829-330cbaf@sha256:5c54f614fb8ee7939492aa4b7d74b37922d98199f5993f6d957a1637ce30eb9e
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:7.4.0-1764684255-8506ae2@sha256:82b0f05c513ccaa1916537b0784df4dda4ea23f0ffc46d4d8043b74ef35ee19a
ARG CILIUM_IPTABLES_IMAGE=quay.io/cilium/iptables:1.8.8-1-1764684255-8506ae2@sha256:038abab3de749feda1f9dbc0f86ed5777e6eb15f6f5f19fa2fd36322c8a7e1bd

FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist
FROM ${CILIUM_IPTABLES_IMAGE} AS iptables-dist

FROM ${GOLANG_IMAGE} AS go-builder

WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    --mount=target=/root/.cache,type=cache \
    --mount=target=/go/pkg/mod,type=cache \
    ./build-gops.sh

ARG TARGETARCH
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    --mount=target=/root/.cache,type=cache \
    --mount=target=/go/pkg/mod,type=cache \
    ./download-cni.sh

FROM ${COMPILERS_IMAGE} AS llvm-builder

ARG LLVM_VERSION="llvmorg-19.1.7"
ADD https://github.com/llvm/llvm-project/archive/${LLVM_VERSION}.tar.gz /tmp/llvm.tar.gz
WORKDIR /src/llvm
RUN tar -xf /tmp/llvm.tar.gz --strip-components=1 --directory /src/llvm
WORKDIR /src/llvm/llvm/build
RUN cmake .. -G "Ninja" \
    -DLLVM_TARGETS_TO_BUILD="BPF" \
    -DLLVM_ENABLE_PROJECTS="clang" \
    -DBUILD_SHARED_LIBS="OFF" \
    -DLLVM_BUILD_STATIC="ON" \
    -DCMAKE_CXX_FLAGS="-s -flto" \
    -DCMAKE_BUILD_TYPE="Release" \
    -DLLVM_BUILD_RUNTIME="OFF" \
    -DCMAKE_INSTALL_PREFIX="/usr/local" \
    && ninja clang llc \
    && strip bin/clang \
    && strip bin/llc

FROM ${UBUNTU_IMAGE} AS rootfs

# Change the number to force the generation of a new git-tree SHA. Useful when
# we want to re-run 'apt-get upgrade' for stale images.
ENV FORCE_BUILD=4

# Update ubuntu packages to the most recent versions
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y jq

WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    ./install-runtime-deps.sh

COPY --from=iptables-dist /iptables /iptables
RUN dpkg -i /iptables/*\.deb && rm -rf /iptables

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    ./iptables-wrapper-installer.sh --no-sanity-check

COPY --from=llvm-builder /src/llvm/llvm/build/bin/clang /src/llvm/llvm/build/bin/llc /usr/local/bin/
COPY --from=bpftool-dist /usr/local/bin/bpftool /usr/local/bin/bpftool
COPY --from=go-builder /out /

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=rootfs / /
