# syntax=docker/dockerfile:1.1-experimental

# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=docker.io/cilium/cilium-builder-dev:b030f1ed16c21608d78564124a870a18ca485444
ARG CA_CERTIFICATES_IMAGE=docker.io/cilium/ca-certificates:69a9f5d66ff96bf97e8b9dc107e92aa9ddbdc9a8

FROM --platform=linux/amd64 ${CILIUM_BUILDER_IMAGE} as builder

ARG NOSTRIP
ARG LOCKDEBUG

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
  make -C hubble-relay \
    NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG PKG_BUILD=1 \
  && mkdir -p /out/linux/amd64/usr/bin && mv hubble-relay/hubble-relay /out/linux/amd64/usr/bin

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
  env GOARCH=arm64 \
    make -C hubble-relay \
      NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG PKG_BUILD=1 \
  && mkdir -p /out/linux/arm64/usr/bin && mv hubble-relay/hubble-relay /out/linux/arm64/usr/bin


FROM ${CA_CERTIFICATES_IMAGE}
ARG TARGETPLATFORM
LABEL maintainer="maintainer@cilium.io"

COPY --from=builder /out/${TARGETPLATFORM} /

WORKDIR /
CMD ["/usr/bin/hubble-relay"]
