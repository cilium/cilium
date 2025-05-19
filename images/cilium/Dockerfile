# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:d7f7d5014fa792d1df3c1d7d32a80060cc7677d7@sha256:51076a73d500a9f9a28d07ac07be4a8a251124bdf6d2c1a111be2ad189c47ab1
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:dc1734647705f5cd9e02479b3c7fe340c9416dff@sha256:50f2f9c730685d846e61cb9661ddeb987028851e62c308cabcf9ccc85527f0bb
#
# cilium-envoy from github.com/cilium/proxy
#
ARG CILIUM_ENVOY_IMAGE=quay.io/cilium/cilium-envoy:v1.32.6-1747357011-012f99406a53a94b4e5dfdde2a779e0aeb85f06d@sha256:ad3577cf2c1a8673ca07f6e27f4ced07e5918e94c2197897fd7fd1706924ada5

FROM ${CILIUM_ENVOY_IMAGE} AS cilium-envoy

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
# We must override NOSTRIP=1 to ensure binaries include debug symbols for extraction. They will be stripped subsequently
# in accordance with the supplied/default NOSTRIP setting. See "Extract debug symbols" below.
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${TARGETARCH} DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} PKG_BUILD=1 ${MODIFIERS} NOSTRIP=1 \
    build-container install-container-binary

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    # install-bash-completion will execute the bash_completion script. It is
    # fine to run this with same architecture as BUILDARCH since the output of
    # bash_completion is the same for both architectures.
    make GOARCH=${BUILDARCH} DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} PKG_BUILD=1 ${MODIFIERS} \
    install-bash-completion licenses-all && \
    mv LICENSE.all /tmp/install/${TARGETOS}/${TARGETARCH}/LICENSE.all && \
    mkdir -p /tmp/hubble/${TARGETOS}/${TARGETARCH} && \
    cd hubble && \
    make GOOS=${TARGETOS} GOARCH=${TARGETARCH} && \
    mv hubble /tmp/hubble/${TARGETOS}/${TARGETARCH}/hubble

# Extract debug symbols to /tmp/debug and strip the binaries if NOSTRIP is not set.
RUN set -xe && \
    export D=/tmp/debug/${TARGETOS}/${TARGETARCH} && \
    mkdir -p $D && \
    cd /tmp/install/${TARGETOS}/${TARGETARCH} && \
    find . -type f \
      -executable \
      -exec sh -c \
        'filename=$(basename ${0}) && \
         objcopy --only-keep-debug ${0} ${0}.debug && \
         if [ "$NOSTRIP" != "1" ] ; then objcopy --strip-all ${0} && (cd $(dirname ${0}) && objcopy --add-gnu-debuglink=${filename}.debug ${filename}) ; fi && \
         mv -v ${0}.debug ${D}/${filename}.debug' \
      {} \;

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
COPY --from=builder /tmp/install/${TARGETOS}/${TARGETARCH} /
COPY --from=builder /tmp/hubble/${TARGETOS}/${TARGETARCH}/hubble /usr/bin/hubble
RUN /usr/bin/hubble completion bash > /etc/bash_completion.d/hubble
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

# Copy in the debug symbols in case the binaries were stripped
COPY --from=builder /tmp/debug/${TARGETOS}/${TARGETARCH} /usr/lib/debug

# Ensure dlv finds the debug symbols. Due to CGO_ENABLED=0, we have no GNU build-id, so Delve's default search path
# is insufficient.
RUN mkdir -p ${HOME}/.config/dlv && \
    echo 'debug-info-directories: ["/usr/lib/debug/.build-id","/usr/lib/debug"]' > ${HOME}/.config/dlv/config.yml && \
    ln -s /usr/lib/debug/cilium-agent.debug /usr/lib/debug/cilium-agent-bin.debug
