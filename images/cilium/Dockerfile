# syntax=docker/dockerfile:1.2

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:a5ba9ba04c230e4fe86c1eac885de7a911e9ce74@sha256:cb302f02973c69231c3a8837c950ac3ed1c1a1216404d46b9b786e033fed4351
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:1b3d0025051ac0a43cb13b00bc1e25e037b19eda@sha256:e9f05a26c78e4daff91dd3fbec29e1d4fd8e57ff1960178e2f510d72e01b98ee

# cilium-envoy from github.com/cilium/proxy
#
FROM quay.io/cilium/cilium-envoy:12e3081cc292764b1308668cab1e7e523429bedc@sha256:3b43de6e585376cc8037b84b2b4d37bdf41242253987e7ff7f72e4e200e61fb5 as cilium-envoy

#
# Hubble CLI
#
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} as hubble
ARG BUILDPLATFORM
COPY images/cilium/hubble-version.sh /tmp/hubble-version.sh
COPY images/cilium/download-hubble.sh /tmp/download-hubble.sh
RUN /tmp/download-hubble.sh
RUN /out/${BUILDPLATFORM}/bin/hubble completion bash > /out/linux/bash_completion

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
ARG NOOPT
ARG LOCKDEBUG
ARG RACE
ARG V
ARG LIBNETWORK_PLUGIN

#
# Please do not add any dependency updates before the 'make install' here,
# as that will mess with caching for incremental builds!
#
WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    make GOARCH=${TARGETARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} NOOPT=${NOOPT} LOCKDEBUG=${LOCKDEBUG} PKG_BUILD=1 V=${V} LIBNETWORK_PLUGIN=${LIBNETWORK_PLUGIN} \
    DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} build-container install-container-binary

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    # install-bash-completion will execute the bash_completion script. It is
    # fine to run this with same architecture as BUILDARCH since the output of
    # bash_completion is the same for both architectures.
    make GOARCH=${BUILDARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} NOOPT=${NOOPT} LOCKDEBUG=${LOCKDEBUG} PKG_BUILD=1 V=${V} LIBNETWORK_PLUGIN=${LIBNETWORK_PLUGIN} \
    DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} install-bash-completion licenses-all && \
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
RUN echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc
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
