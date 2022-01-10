# syntax=docker/dockerfile:1.2

# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG TESTER_IMAGE=quay.io/cilium/image-tester:eb76f0d4d585946bb0267b4c4478cceed17bbd87@sha256:c9a598cdc4843e62ab4e430f36343ca06d5292506261f17e466e0f1cbb48ddbb
ARG GOLANG_IMAGE=docker.io/library/golang:1.17.6@sha256:d36ec9839e6ebac63a53f3e15758ffa339b81dc5df6c9d41a18a3f9302bd0d90
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:20.04@sha256:cf31af331f38d1d7158470e095b132acd126a7180a54f263d386da88eb681d93

ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:0147a23fdada32bd51b4f313c645bcb5fbe188d6@sha256:24fd3ad32471d0e45844c856c38f1b2d4ac8bd0a2d4edf64cffaaa3fd0b21202
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:7a5420acb4a0fa276a549eb4674515eadb2821d7@sha256:3e204885a1b9ec2a5b593584608664721ef0bd221d3920c091c2e77eb259090c
ARG CILIUM_IPROUTE2_IMAGE=quay.io/cilium/cilium-iproute2:824df0c341c724f4b12cc48762f80aa3d698b589@sha256:0af5e059b2a43c6383a3daa293182b50cb88f7761f543dacf43c1c3f8f79030c

FROM ${CILIUM_LLVM_IMAGE} as llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} as bpftool-dist
FROM ${CILIUM_IPROUTE2_IMAGE} as iproute2-dist

FROM --platform=linux/amd64 ${GOLANG_IMAGE} as gops-cni-builder

RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    ./build-gops.sh
# download-cni.sh will build both archs at the same time
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    ./download-cni.sh

FROM ${UBUNTU_IMAGE} as rootfs

# Change the number to force the generation of a new git-tree SHA. Useful when
# we want to re-run 'apt-get upgrade' for stale images.
ENV FORCE_BUILD=1

# Update ubuntu packages to the most recent versions
RUN apt-get update && \
    apt-get upgrade -y

WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    ./install-runtime-deps.sh

COPY iptables-wrapper /usr/sbin/iptables-wrapper
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    ./configure-iptables-wrapper.sh

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /bin/
COPY --from=bpftool-dist /usr/local /usr/local
COPY --from=iproute2-dist /usr/lib/libbpf* /usr/lib
COPY --from=iproute2-dist /usr/local /usr/local

ARG TARGETPLATFORM
COPY --from=gops-cni-builder /out/${TARGETPLATFORM}/bin/loopback /cni/loopback
COPY --from=gops-cni-builder /out/${TARGETPLATFORM}/bin/gops /bin/gops

FROM ${TESTER_IMAGE} as test
COPY --from=rootfs / /
COPY --from=llvm-dist /test /test
COPY --from=bpftool-dist /test /test
COPY --from=iproute2-dist /test /test
RUN /test/bin/cst -C /test/llvm
RUN /test/bin/cst -C /test/bpftool
RUN /test/bin/cst -C /test/iproute2

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=rootfs / /
