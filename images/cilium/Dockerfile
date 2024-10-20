# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:a7339df5934d72e975c12844142436ab6b4df0fc@sha256:5301fb9227ee7617dfda3134f647ed4b8bc0a0f6c6a625ec94e520005dfdf1ad
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:60deba35baf009a40213fdd9fb36145d8534f4bd@sha256:d7e1a37214e5b16d5d8759c559ba7b24fbd61447f2555105aaef169af7438e6f
#
# cilium-envoy from github.com/cilium/proxy
#
FROM quay.io/cilium/cilium-envoy:v1.29.9-1728899856-79cb2919a745b6805864ef3ced869bb82b309c09@sha256:0e9165a36f8e68cb8c0ca8806d44ebd476850b158a25bae9fe19d46c699d5268 as cilium-envoy

#
# Hubble CLI
#
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} AS hubble
ARG BUILDPLATFORM
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
FROM --platform=${BUILDPLATFORM} ${CILIUM_BUILDER_IMAGE} AS builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
# MODIFIERS are extra arguments to be passed to make at build time.
ARG MODIFIERS

#
# Please do not add any dependency updates before the 'make install' here,
# as that will mess with caching for incremental builds!
#
WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${TARGETARCH} DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} PKG_BUILD=1 ${MODIFIERS} \
    build-container install-container-binary

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    # install-bash-completion will execute the bash_completion script. It is
    # fine to run this with same architecture as BUILDARCH since the output of
    # bash_completion is the same for both architectures.
    make GOARCH=${BUILDARCH} DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} PKG_BUILD=1 ${MODIFIERS} \
    install-bash-completion licenses-all && \
    mv LICENSE.all /tmp/install/${TARGETOS}/${TARGETARCH}/LICENSE.all

COPY images/cilium/init-container.sh \
     plugins/cilium-cni/install-plugin.sh \
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
FROM ${CILIUM_RUNTIME_IMAGE} AS release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
RUN echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc
COPY --from=cilium-envoy /usr/lib/libcilium.so /usr/lib/libcilium.so
COPY --from=cilium-envoy /usr/bin/cilium-envoy /usr/bin/cilium-envoy-starter /usr/bin/
# When used within the Cilium container, Hubble CLI should target the
# local unix domain socket instead of Hubble Relay.
ENV HUBBLE_SERVER=unix:///var/run/cilium/hubble.sock
COPY --from=hubble /out/${TARGETOS}/${TARGETARCH}/bin/hubble /usr/bin/hubble
COPY --from=hubble /out/linux/bash_completion /etc/bash_completion.d/hubble

COPY --from=builder /tmp/install/${TARGETOS}/${TARGETARCH} /
WORKDIR /home/cilium

ENV INITSYSTEM="SYSTEMD"
CMD ["/usr/bin/cilium-dbg"]

#
# Cilium debug image.
#
# Typical image bulids will stop above at the 'release' target, but
# developers follow this Dockerfile to the end. Starting from a release
# image, install delve debugger and wrap the cilium-agent binary calls
# with a script that automatically provisions the debugger on a
# dedicated port.
FROM release AS debug
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG DEBUG_HOLD
ENV DEBUG_HOLD=${DEBUG_HOLD}
COPY --from=builder /tmp/install/${TARGETOS}/${TARGETARCH}/usr/bin/cilium-agent /usr/bin/cilium-agent-bin
COPY --from=builder /go/bin/dlv /usr/bin/dlv
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/bin/debug-wrapper /usr/bin/cilium-agent
