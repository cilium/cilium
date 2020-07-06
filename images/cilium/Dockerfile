# syntax=docker/dockerfile:1.1-experimental

# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=docker.io/cilium/cilium-builder-dev:b030f1ed16c21608d78564124a870a18ca485444
ARG CILIUM_RUNTIME_IMAGE=docker.io/cilium/cilium-runtime-dev:74992a84a55860ffe1b0c4d6b702c8520db0d4b1

FROM --platform=linux/amd64 ${CILIUM_BUILDER_IMAGE} as builder

ARG NOSTRIP
ARG LOCKDEBUG

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
  make clean-container build-container install-container \
    NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG PKG_BUILD=1 SKIP_DOCS=true DESTDIR=/out/linux/amd64

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
  env GOARCH=arm64 CC=aarch64-linux-gnu-gcc \
    make clean-container build-container install-container \
      NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG PKG_BUILD=1 SKIP_DOCS=true DESTDIR=/out/linux/arm64 \
      HOST_CC=aarch64-linux-gnu-gcc HOST_STRIP=aarch64-linux-gnu-strip

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
  cd /go/src/github.com/cilium/cilium/plugins/cilium-cni \
    && cp cni-install.sh cni-uninstall.sh /out/linux/amd64 \
    && cp cni-install.sh cni-uninstall.sh /out/linux/arm64

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
  cd /go/src/github.com/cilium/cilium/contrib/packaging/docker \
    && cp init-container.sh /out/linux/amd64 \
    && cp init-container.sh /out/linux/arm64

FROM ${CILIUM_RUNTIME_IMAGE}
ARG TARGETPLATFORM
LABEL maintainer="maintainer@cilium.io"

COPY --from=builder /out/${TARGETPLATFORM} /

WORKDIR /home/cilium

RUN groupadd -f cilium \
    && echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc

CMD ["/usr/bin/cilium"]
