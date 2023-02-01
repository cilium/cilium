# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:e81f0ce3895bab461a5125b73551790a1d65e91d@sha256:ca4c1a9544c868b87a99f72f64b1d58044d294ae62c0074aa1ded4ef3369abb1
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:d3a7d5d4b2583b0f8292a0438c8a5115585e2cc0@sha256:e678c0a2e0c873a63e47560f923a202a08e3ff5c1817c78c5f31b60cfae2e2ec

# cilium-envoy from github.com/cilium/proxy
#
FROM quay.io/cilium/cilium-envoy:d59b7f950565d4ccad5c9e30f725740271b7f1c2@sha256:a9c20ee37fe8b280606b096f34f074fed02a347381ded71f1853a214a324a9ef as cilium-envoy

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
FROM ${CILIUM_RUNTIME_IMAGE} as release
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

#
# Cilium debug image.
#
# Typical image bulids will stop above at the 'release' target, but
# developers follow this Dockerfile to the end. Starting from a release
# image, install delve debugger and wrap the cilium-agent binary calls
# with a script that automatically provisions the debugger on a
# dedicated port.
FROM release as debug
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
COPY --from=builder /go/bin/dlv /usr/bin/dlv
RUN mv /usr/bin/cilium-agent /usr/bin/cilium-agent-bin
COPY images/scripts/debug-wrapper.sh /usr/bin/cilium-agent
