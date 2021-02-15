# syntax=docker/dockerfile:1.1-experimental

# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=docker.io/cilium/cilium-builder-dev:9f7c5a373facf77a3eaab0f68ff64a5d1fa18229
ARG CA_CERTIFICATES_IMAGE=docker.io/cilium/ca-certificates:69a9f5d66ff96bf97e8b9dc107e92aa9ddbdc9a8

FROM ${CILIUM_BUILDER_IMAGE} as builder

ARG TARGETOS
ARG TARGETARCH
ARG NOSTRIP
ARG LOCKDEBUG
ARG RACE

ENV GOOS=${TARGETOS} \
  GOARCH=${TARGETARCH}

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
  make -C operator \
  NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG RACE=$RACE PKG_BUILD=1 \
  && mkdir -p /out/${TARGETOS}/${TARGETARCH}/usr/bin && mv operator/cilium-operator* /out/${TARGETOS}/${TARGETARCH}/usr/bin

FROM ${CA_CERTIFICATES_IMAGE}

ARG TARGETOS
ARG TARGETARCH

LABEL maintainer="maintainer@cilium.io"

WORKDIR /
ENV GOPS_CONFIG_DIR=/

COPY --from=builder /out/${TARGETOS}/${TARGETARCH} .

CMD ["/usr/bin/cilium-operator-generic"]
