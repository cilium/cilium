# syntax=docker/dockerfile:1.1-experimental

# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:e3923f9b4709bddd4cd123d4f7e9fdcdd17f2a59@sha256:d32050b9fbdb60fd5579260a8d7027f911aa5cd115e43dfc21c39f7ce2fc490a
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

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
  go build -o /out/linux/amd64/usr/local/bin/ginkgo github.com/onsi/ginkgo/ginkgo

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
  env GOARCH=arm64 CC=aarch64-linux-gnu-gcc \
    go build -o /out/linux/arm64/usr/local/bin/ginkgo github.com/onsi/ginkgo/ginkgo

WORKDIR /go/src/github.com/cilium/cilium/test

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
  /out/linux/amd64/usr/local/bin/ginkgo build ./ && mv test.test /out/linux/amd64/usr/local/bin/cilium-test

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
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
