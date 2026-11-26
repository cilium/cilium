# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_IMAGE=docker.io/library/golang:1.26.11@sha256:6e59e17a20f13c102e49d82dffab66d41cffe6c266b225d82794328aea859ab5
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db

ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:19.1.7-1788264345-cbe387d@sha256:9dbf0536ebf99f08bb3989faa8d85aef7345552f322bd745898a6116eef11a6d
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:7.8.1-1795524785-cb0d769@sha256:ecb7e2528baaedd0e1516513062b228051aa3ff1854ff4cdc22cf3d1e5de7d21
ARG CILIUM_IPTABLES_IMAGE=quay.io/cilium/iptables:1.8.8-1-1793634007-0b329bb@sha256:035ed5ed5f20dae807ec221b62266677f824dbfc564e8202078a82e316b9097a

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist
FROM ${CILIUM_IPTABLES_IMAGE} AS iptables-dist

FROM ${GOLANG_IMAGE} AS go-builder

WORKDIR /go/src/github.com/cilium/cilium/images/runtime
ARG TARGETARCH
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    --mount=target=/root/.cache,type=cache \
    --mount=target=/go/pkg/mod,type=cache \
    ./build-gops.sh

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    --mount=target=/root/.cache,type=cache \
    --mount=target=/go/pkg/mod,type=cache \
    ./build-cni.sh

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    --mount=target=/root/.cache,type=cache \
    --mount=target=/go/pkg/mod,type=cache \
    ./build-iptables-wrapper.sh

FROM ${UBUNTU_IMAGE} AS rootfs

# Change the number to force the generation of a new git-tree SHA. Useful when
# we want to re-run 'apt-get upgrade' for stale images.
ENV FORCE_BUILD=4

# Update ubuntu packages to the most recent versions
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y jq

# The Ubuntu image ships pebble outside dpkg and Cilium never runs it
RUN rm -rf /usr/bin/pebble /var/lib/pebble

WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    ./install-runtime-deps.sh

COPY --from=iptables-dist /iptables /iptables
RUN dpkg -i /iptables/*\.deb && rm -rf /iptables

COPY --from=go-builder /out /

# Symlink the iptables and ip6tables binaries to the iptables-wrapper binary.
# On its first invocation the wrapper detects whether the host is using the
# legacy or nft iptables backend and re-points these symlinks at the matching
# backend before re-execing the original command.
RUN /usr/sbin/iptables-wrapper install

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/
COPY --from=bpftool-dist /usr/local/bin/bpftool /usr/local/bin/bpftool

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=rootfs / /
