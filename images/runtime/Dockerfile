# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG TESTER_IMAGE=quay.io/cilium/image-tester:dd09c8d3ef349a909fbcdc99279516baef153f22@sha256:c056d064cb47c97acd607343db5457e1d49d9338d6d8a87e93e23cc93f052c73
ARG GOLANG_IMAGE=docker.io/library/golang:1.22.4@sha256:c2010b9c2342431a24a2e64e33d9eb2e484af49e72c820e200d332d214d5e61f
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:24.04@sha256:2e863c44b718727c860746568e1d54afd13b2fa71b160f5cd9058fc436217b30

ARG CILIUM_LLVM_IMAGE=docker.io/sayboras/cilium-llvm:f16f89edd7579bf48dc6d984799fec386fe7cbef@sha256:5d76dbbca6d5435422afe98dd9ebb7e7f437d3ef60318343353bfd491e2ae6a9
ARG CILIUM_BPFTOOL_IMAGE=docker.io/sayboras/cilium-bpftool:5a9c4852a21287686009bfe1cdc1fed6e7aabdea@sha256:895f7405acb09506c2fe411112a86cdab51f08c0fe65dc8da32b11359c88ae31
ARG CILIUM_IPTABLES_IMAGE=docker.io/sayboras/iptables:1331e9b1b03f70c9d8b08626d9a7126963f86478@sha256:1e87279f5436d14039340377c12b58f71fe61e76abd763d9a51ed7f75cb38992

FROM ${CILIUM_LLVM_IMAGE} as llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} as bpftool-dist
FROM ${CILIUM_IPTABLES_IMAGE} as iptables-dist

FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as gops-cni-builder

RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu

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
ENV FORCE_BUILD=3

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
COPY --from=bpftool-dist /usr/local /usr/local

ARG TARGETPLATFORM
COPY --from=gops-cni-builder /out/${TARGETPLATFORM}/bin/loopback /cni/loopback
COPY --from=gops-cni-builder /out/${TARGETPLATFORM}/bin/gops /bin/gops

FROM ${TESTER_IMAGE} as test
COPY --from=rootfs / /
COPY --from=llvm-dist /test /test
COPY --from=bpftool-dist /test /test
RUN /test/bin/cst -C /test/llvm
RUN /test/bin/cst -C /test/bpftool

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=rootfs / /
