# syntax=docker/dockerfile:1.2

# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:374a7ec10c5cbc5e9afe4cdd376f95ca592bd9ab@sha256:8d59be6168a25a9855707d63596df9903eef32518710a83879efbf9222f07628
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:a1ab864ff010f09a004f4545241a025113d07f4a@sha256:ab07f7251f96d9a943360d15bfe541b96db0a92e1523883f9502371b4d3a6902

# cilium-envoy from github.com/cilium/proxy
#
FROM quay.io/cilium/cilium-envoy:9b1701da9cc035a1696f3e492ee2526101262e56@sha256:c0e0586bf97e69b9c16c95eff707a264c1c00bb89371205e88f6849d12ed2de2 as cilium-envoy

#
# Hubble CLI
#
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} as hubble
COPY images/cilium/hubble-version.sh /tmp/hubble-version.sh
COPY images/cilium/download-hubble.sh /tmp/download-hubble.sh
RUN /tmp/download-hubble.sh
RUN /out/linux/amd64/bin/hubble completion bash > /out/linux/bash_completion

#
# Cilium incremental build. Should be fast given builder-deps is up-to-date!
#
# cilium-builder tag is the date on which the compatible build image
# was pushed.  If a new version of the build image is needed, it needs
# to be tagged with a new date and this file must be changed
# accordingly.  Keeping the old images available will allow older
# versions to be built while allowing the new versions to make changes
# that are not backwards compatible.
#
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} as builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG NOSTRIP
ARG LOCKDEBUG
ARG RACE
ARG V
ARG LIBNETWORK_PLUGIN

#
# Please do not add any dependency updates before the 'make install' here,
# as that will mess with caching for incremental builds!
#
WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    make IMAGE_CROSS_TARGET_PLATFORM=${TARGETOS}/${TARGETARCH} GOARCH=${TARGETARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} LOCKDEBUG=${LOCKDEBUG} PKG_BUILD=1 V=${V} LIBNETWORK_PLUGIN=${LIBNETWORK_PLUGIN} \
    SKIP_DOCS=true DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} build-container install-container-binary

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    # install-bash-completion will execute the bash_completion script. It is
    # fine to run this with same architecture as BUILDARCH since the output of
    # bash_completion is the same for both architectures.
    make GOARCH=${BUILDARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} LOCKDEBUG=${LOCKDEBUG} PKG_BUILD=1 V=${V} LIBNETWORK_PLUGIN=${LIBNETWORK_PLUGIN} \
    SKIP_DOCS=true DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} install-bash-completion licenses-all && \
    mv LICENSE.all /tmp/install/${TARGETOS}/${TARGETARCH}/LICENSE.all

COPY images/cilium/init-container.sh \
     plugins/cilium-cni/cni-install.sh \
     plugins/cilium-cni/cni-uninstall.sh \
       /tmp/install/${TARGETOS}/${TARGETARCH}

#
# Cilium runtime install.
#
# cilium-runtime tag is a date on which the compatible runtime base
# was pushed.  If a new version of the runtime is needed, it needs to
# be tagged with a new date and this file must be changed accordingly.
# Keeping the old runtimes available will allow older versions to be
# built while allowing the new versions to make changes that are not
# backwards compatible.
#
FROM ${CILIUM_RUNTIME_IMAGE}
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
RUN groupadd -f cilium \
    && echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc
COPY --from=cilium-envoy / /
# When used within the Cilium container, Hubble CLI should target the
# local unix domain socket instead of Hubble Relay.
ENV HUBBLE_SERVER=unix:///var/run/cilium/hubble.sock
COPY --from=hubble /out/${TARGETOS}/${TARGETARCH}/bin/hubble /usr/bin/hubble
COPY --from=hubble /out/linux/bash_completion /etc/bash_completion.d/hubble

COPY --from=builder /tmp/install/${TARGETOS}/${TARGETARCH} /
WORKDIR /home/cilium

ENV INITSYSTEM="SYSTEMD"
CMD ["/usr/bin/cilium"]
