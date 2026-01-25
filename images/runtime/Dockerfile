# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_IMAGE=docker.io/library/golang:1.25.6@sha256:ce63a16e0f7063787ebb4eb28e72d477b00b4726f79874b3205a965ffd797ab2
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:24.04@sha256:cd1dba651b3080c3686ecf4e3c4220f026b521fb76978881737d24f200828b2b

ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:19.1.7-1769028416-0a7185e@sha256:48ce0bbdf57b21866db310f364f2e0a2552a19ccc85d709d76690a6aa6338f06
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:7.6.0-1768387623-54f9852@sha256:7db5e646accf881f852d9d9d895cfeabe9b332d9f83c5edb070aaf40d7a649df
ARG CILIUM_IPTABLES_IMAGE=quay.io/cilium/iptables:1.8.8-1-1764684255-8506ae2@sha256:038abab3de749feda1f9dbc0f86ed5777e6eb15f6f5f19fa2fd36322c8a7e1bd

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
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

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/
COPY --from=bpftool-dist /usr/local/bin/bpftool /usr/local/bin/bpftool
COPY --from=go-builder /out /

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=rootfs / /
