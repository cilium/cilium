# syntax=docker/dockerfile:1.1-experimental

# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=docker.io/cilium/image-compilers:57f235db9a07e81c5b60c536498ecbf2501dd267@sha256:080245ac0d7d061e05613e6bf887dc3c8bb07392cd2ce265b8a4aaaad17f2125
ARG TESTER_IMAGE=docker.io/cilium/image-tester:70724309b859786e0a347605e407c5261f316eb0@sha256:89cc1f577d995021387871d3dbeb771b75ab4d70073d9bcbc42e532792719781
ARG GOLANG_IMAGE=docker.io/library/golang:1.14.4@sha256:d39a459086c75920390c9b9d42bbc7c52fef1fe7666e7633a02508c607c889d4
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:20.04@sha256:8bce67040cd0ae39e0beb55bcb976a824d9966d2ac8d2e4bf6119b45505cee64

ARG CILIUM_LLVM_IMAGE=docker.io/cilium/cilium-llvm:3355296c86c669ca92077e37bd5901d41c8142b9
ARG CILIUM_BPFTOOL_IMAGE=docker.io/cilium/cilium-bpftool:fbb2e86339609f6755f53fcefd2257e4beea4423
ARG CILIUM_IPROUTE2_IMAGE=docker.io/cilium/cilium-iproute2:44d4c6ebc57b78af0f1080ef52da2bae2605a439

FROM ${CILIUM_LLVM_IMAGE} as llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} as bpftool-dist
FROM ${CILIUM_IPROUTE2_IMAGE} as iproute2-dist

FROM --platform=linux/amd64 ${COMPILERS_IMAGE} as builder

COPY cni-version.sh /tmp/cni-version.sh
COPY download-cni.sh /tmp/download-cni.sh
RUN /tmp/download-cni.sh

FROM --platform=linux/amd64 ${GOLANG_IMAGE} as go-builder

COPY build-gops.sh /tmp/build-gops.sh
RUN --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache /tmp/build-gops.sh

FROM ${UBUNTU_IMAGE} as rootfs

COPY install-runtime-deps.sh /tmp/install-runtime-deps.sh 
RUN /tmp/install-runtime-deps.sh

COPY iptables-wrapper /usr/sbin/iptables-wrapper
COPY configure-iptables-wrapper.sh /tmp/configure-iptables-wrapper.sh
RUN /tmp/configure-iptables-wrapper.sh

COPY --from=llvm-dist /usr/local /usr/local
COPY --from=bpftool-dist /usr/local /usr/local
COPY --from=iproute2-dist /usr/local /usr/local

ARG TARGETPLATFORM
COPY --from=builder /out/${TARGETPLATFORM}/bin /bin
COPY --from=go-builder /out/${TARGETPLATFORM}/bin /bin

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
