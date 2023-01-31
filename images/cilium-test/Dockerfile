# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:e81f0ce3895bab461a5125b73551790a1d65e91d@sha256:ca4c1a9544c868b87a99f72f64b1d58044d294ae62c0074aa1ded4ef3369abb1
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:22.04@sha256:f05532b6a1dec5f7a77a8d684af87bc9cd1f2b32eab301c109f8ad151b5565d1

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
