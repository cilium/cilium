# syntax=docker/dockerfile:1.1-experimental

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:a2dc3278c48e1593b1f6c8fd9e5c6a982d56a875@sha256:98c4e694805e9a9d410ed73d555e97e91d77e2ab4529b6b51f5243b33ab411b1
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:20.04@sha256:cf31af331f38d1d7158470e095b132acd126a7180a54f263d386da88eb681d93

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

FROM scratch
ARG TARGETPLATFORM
LABEL maintainer="maintainer@cilium.io"
COPY --from=rootfs / /
COPY --from=builder /out/${TARGETPLATFORM} /
COPY test /usr/local/src/cilium/test
COPY install/kubernetes /usr/local/src/cilium/install/kubernetes
COPY images/cilium-test/cilium-test-gke.sh /usr/local/bin/cilium-test-gke.sh
