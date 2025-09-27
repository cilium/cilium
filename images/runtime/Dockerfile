# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_IMAGE=docker.io/library/golang:1.25.1@sha256:8305f5fa8ea63c7b5bc85bd223ccc62941f852318ebfbd22f53bbd0b358c07e1
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:24.04@sha256:9cbed754112939e914291337b5e554b07ad7c392491dba6daf25eef1332a22e8

ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:1755027449-dfe66ec@sha256:6a8632f1772dee0f1f287dd84f4010347c19f350347487603f16210674a3a787
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:1755027374-a7874bb@sha256:fd086a4b94e5e076039fbb32ce31edbcc8d443fab522965ab5643034f36d3c41
ARG CILIUM_IPTABLES_IMAGE=quay.io/cilium/iptables:1331e9b1b03f70c9d8b08626d9a7126963f86478@sha256:d761d967243aced2729adde1e332a9c9def6baeb61f5f6cde5758b04e9a79355

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist
FROM ${CILIUM_IPTABLES_IMAGE} AS iptables-dist

FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS gops-cni-builder

RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    ./build-gops.sh
# download-cni.sh will build both archs at the same time
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
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

ARG TARGETPLATFORM
COPY --from=gops-cni-builder /out/${TARGETPLATFORM}/bin/loopback /cni/loopback
COPY --from=gops-cni-builder /out/${TARGETPLATFORM}/bin/gops /bin/gops

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=rootfs / /
