# syntax=docker/dockerfile:1.1-experimental

# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=docker.io/cilium/cilium-builder-dev:2be3763997e9439d3711f80741944b92f0c28ea9
ARG CILIUM_RUNTIME_IMAGE=docker.io/cilium/cilium-runtime-dev:e852cc7caf2d7a24102c05786f12b96eb106a2a0

FROM ${CILIUM_BUILDER_IMAGE} as builder

ARG TARGETOS
ARG TARGETARCH
ARG NOSTRIP
ARG LOCKDEBUG
ARG RACE

ENV GOOS=${TARGETOS} \
  GOARCH=${TARGETARCH}

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
  if [ "${TARGETOS}/${TARGETARCH}" = "linux/arm64" ] ; then export CC=aarch64-linux-gnu-gcc ; fi ; \
    make build-container install-container \
      NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG RACE=$RACE PKG_BUILD=1 SKIP_DOCS=true DESTDIR=/out/${TARGETOS}/${TARGETARCH} IMAGE_CROSS_TARGET_PLATFORM=${TARGETOS}/${TARGETARCH}

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
  cd /go/src/github.com/cilium/cilium/plugins/cilium-cni \
  && cp cni-install.sh cni-uninstall.sh /out/${TARGETOS}/${TARGETARCH}

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
  cd /go/src/github.com/cilium/cilium/contrib/packaging/docker \
  && cp init-container.sh /out/${TARGETOS}/${TARGETARCH}

FROM ${CILIUM_RUNTIME_IMAGE}

ARG TARGETOS
ARG TARGETARCH

LABEL maintainer="maintainer@cilium.io"

COPY --from=builder /out/${TARGETOS}/${TARGETARCH} /

WORKDIR /home/cilium

RUN echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc

CMD ["/usr/bin/cilium"]
