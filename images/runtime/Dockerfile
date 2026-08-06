# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_IMAGE=docker.io/library/golang:1.26.5@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:26.04@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03

ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:19.1.7-1782898005-bed4da5@sha256:270bf0e70853c388b72c2247e4ade91d35d74898e2ec12edd5b72ace9ee34333
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:7.7.0-1785833026-d8383c5@sha256:5ea5cf5bd61b8a41102b8ce7116fd2ba65993ee7006d86652bdeac428dbf001f

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist

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
# we want to re-run 'apt-get upgrade' (in install-runtime-deps.sh) for stale
# images.
ENV FORCE_BUILD=4

WORKDIR /go/src/github.com/cilium/cilium/images/runtime
# install-runtime-deps.sh upgrades the base packages, installs the runtime dependencies,
# then purges apt. It is the last apt-based step in this image: dpkg-based steps below
# (iptables) still work, but no apt-get can run after this point.
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    ./install-runtime-deps.sh

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
