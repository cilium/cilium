# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_IMAGE=docker.io/library/golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:26.04@sha256:f144425ff09be612d6d9ad965196e9cdc23dae1f42110a8a11a3e9a8198759f7

ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:19.1.7-1788264345-cbe387d@sha256:9dbf0536ebf99f08bb3989faa8d85aef7345552f322bd745898a6116eef11a6d
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:7.7.0-1791281887-945ab05@sha256:0807fec65047c62cdf59e8e9f294bcac9133e005e781c1d10cc60c20e036d07c
ARG CILIUM_IPTABLES_IMAGE=quay.io/cilium/iptables:1.8.8-1-1791281887-945ab05@sha256:126e83902875c07b0417bdd2ddd46b7efbef85bb3875da16d2a29f4719ded4f6

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
