# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:1b8f97cf70e2a4e7b0609f259d9540523c50cc9f@sha256:0b18c799b88ec039cb0d6d6338ddf539f530319960f9dbc22b69ec6167d3c2ec
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:22.04@sha256:27cb6e6ccef575a4698b66f5de06c7ecd61589132d5a91d098f7f3f9285415a9

FROM ${UBUNTU_IMAGE} as rootfs
ARG TARGETPLATFORM

COPY images/cilium-test/install-deps.sh /tmp/install-deps.sh
RUN /tmp/install-deps.sh

COPY images/cilium-test/install-helm.sh /tmp/install-helm.sh
RUN /tmp/install-helm.sh "${TARGETPLATFORM}"

FROM --platform=linux/amd64 ${CILIUM_BUILDER_IMAGE} as builder

RUN mkdir -p /out/linux/amd64/usr/local/bin /out/linux/arm64/usr/local/bin

WORKDIR /go/src/github.com/cilium/cilium/images/cilium-test

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
  go build -o /out/linux/amd64/usr/local/bin/ginkgo github.com/onsi/ginkgo/ginkgo

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
  env GOARCH=arm64 CC=aarch64-linux-gnu-gcc \
    go build -o /out/linux/arm64/usr/local/bin/ginkgo github.com/onsi/ginkgo/ginkgo

WORKDIR /go/src/github.com/cilium/cilium/test

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
  /out/linux/amd64/usr/local/bin/ginkgo build ./ && mv test.test /out/linux/amd64/usr/local/bin/cilium-test

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
  env GOARCH=arm64 CC=aarch64-linux-gnu-gcc \
    /out/linux/amd64/usr/local/bin/ginkgo build ./ && mv test.test /out/linux/arm64/usr/local/bin/cilium-test

FROM scratch as release
ARG TARGETPLATFORM
LABEL maintainer="maintainer@cilium.io"
COPY --from=rootfs / /
COPY --from=builder /out/${TARGETPLATFORM} /
COPY test /usr/local/src/cilium/test
COPY install/kubernetes /usr/local/src/cilium/install/kubernetes
COPY images/cilium-test/cilium-test-gke.sh /usr/local/bin/cilium-test-gke.sh
