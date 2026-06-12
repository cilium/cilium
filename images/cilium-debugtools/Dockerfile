# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# renovate: datasource=docker
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:7fdeaeec57c8e59cdcef4014ae34c7fdf5be2ef6@sha256:d21b12a3bb16d3bfcf49518fcb8218ff03b163e91d7ae7cbc39b558cf4aa2b10
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:7.6.0-1772622536-65b121f@sha256:7bd6330b1d92eb1e923cd7d1ad44808ac7598b4661a6726fabf24407a95f5bde
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c

FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist

FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} AS builder

ARG TARGETOS
ARG TARGETARCH
ARG MODIFIERS

WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${TARGETARCH} DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} PKG_BUILD=1 $(echo $MODIFIERS | tr -d '"') \
    build-container install-container-binary

FROM ${UBUNTU_IMAGE} AS release

ARG TARGETOS
ARG TARGETARCH

LABEL maintainer="maintainer@cilium.io"

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      bash \
      curl \
      dnsutils \
      netcat-openbsd \
      iperf3 \
      iputils-ping \
      tcpdump \
      iproute2 \
      iptables \
      nftables \
      conntrack \
      net-tools \
      ethtool \
      jq \
      tree \
      procps \
      lsof \
      less \
      strace \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /go/src/github.com/cilium/cilium/images/cilium-debugtools
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/cilium-debugtools \
    ./install-tools.sh

COPY --from=bpftool-dist /usr/local/bin/bpftool /usr/local/bin/bpftool

COPY --from=builder /tmp/install/${TARGETOS}/${TARGETARCH}/usr/bin/cilium-dbg /usr/local/bin/cilium-dbg
COPY --from=builder /tmp/install/${TARGETOS}/${TARGETARCH}/usr/bin/cilium-bugtool /usr/local/bin/cilium-bugtool
COPY --from=builder /tmp/install/${TARGETOS}/${TARGETARCH}/usr/bin/hubble /usr/local/bin/hubble

# cilium-dbg as primary entry point  drop to a shell by default
CMD ["/bin/bash"]
