# check=error=true

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:a56e5161e120f4da5b976dc44dd984ddbe824d1e@sha256:5faf99168fda51d2104f4e1e6141ed95dbe9a3c864941687035ae69d5da33c52
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:91d128557c77151b7b16b69b76b8dc41e498ec33@sha256:fa2f8d980fdc0c0a04790bb3c2981712994f463ea765e07196ed88cc1e5ae304
#
# cilium-envoy from github.com/cilium/proxy
#
ARG CILIUM_ENVOY_IMAGE=quay.io/cilium/cilium-envoy:v1.35.9-1767794330-db497dd19e346b39d81d7b5c0dedf6c812bcc5c9@sha256:81398e449f2d3d0a6a70527e4f641aaa685d3156bea0bb30712fae3fd8822b86

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
    make GOARCH=${TARGETARCH} DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} PKG_BUILD=1 $(echo $MODIFIERS | tr -d '"') NOSTRIP=1 \
    build-container install-container-binary

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    # install-bash-completion will execute the bash_completion script. It is
    # fine to run this with same architecture as BUILDARCH since the output of
    # bash_completion is the same for both architectures.
    make GOARCH=${BUILDARCH} DESTDIR=/tmp/install/${TARGETOS}/${TARGETARCH} PKG_BUILD=1 $(echo $MODIFIERS | tr -d '"') \
    install-bash-completion licenses-all && \
    mv LICENSE.all /tmp/install/${TARGETOS}/${TARGETARCH}/LICENSE.all

# Extract debug symbols to /tmp/debug and strip the binaries if NOSTRIP is not set.
# Use the appropriate objcopy for the target architecture.
RUN set -xe && \
    export D=/tmp/debug/${TARGETOS}/${TARGETARCH} && \
    cd /tmp/install/${TARGETOS}/${TARGETARCH} && \
    find . -type f \
      -executable \
      -exec sh -c \
        'OBJCOPY_CMD=objcopy; \
         if [ "${TARGETARCH}" = "amd64" ]; then OBJCOPY_CMD=x86_64-linux-gnu-objcopy; \
         elif [ "${TARGETARCH}" = "arm64" ]; then OBJCOPY_CMD=aarch64-linux-gnu-objcopy; \
         fi; \
         filename=$(basename ${0}) && \
         ${OBJCOPY_CMD} --only-keep-debug ${0} ${0}.debug && \
         if ! echo "$MODIFIERS" | grep "NOSTRIP=1" ; then ${OBJCOPY_CMD} --strip-all ${0} && (cd $(dirname ${0}) && ${OBJCOPY_CMD} --add-gnu-debuglink=${filename}.debug ${filename}) ; fi && \
         mkdir -p $(dirname ${D}/${0}) && \
         mv -v ${0}.debug ${D}/${0}.debug' \
      {} \;

# Check debug symbols are present
RUN for f in $(find /tmp/debug -type f -name '*.debug') ; do readelf -S ${f} | grep -q \\.symtab || \
    (echo Debug symbols are missing in ${f} - possibly due to incorrect build parameters && false); done

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
COPY --from=cilium-envoy /usr/bin/cilium-envoy /usr/bin/cilium-envoy-starter /usr/bin/
# When used within the Cilium container, Hubble CLI should target the
# local unix domain socket instead of Hubble Relay.
ENV HUBBLE_SERVER=unix:///var/run/cilium/hubble.sock
COPY --from=builder /tmp/install/${TARGETOS}/${TARGETARCH} /
WORKDIR /home/cilium

ENV INITSYSTEM="SYSTEMD"
CMD ["/usr/bin/cilium-dbg"]

#
# Cilium debug image.
#
# Typical image builds will stop above at the 'release' target, but
# developers follow this Dockerfile to the end. Starting from a release
# image, install delve debugger and wrap the cilium-agent binary calls
# with a script that automatically provisions the debugger on a
# dedicated port.
FROM ${CILIUM_BUILDER_IMAGE} AS debug-tools
FROM release AS debug
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG DEBUG_HOLD
ENV DEBUG_HOLD=${DEBUG_HOLD}
COPY --from=builder /tmp/install/${TARGETOS}/${TARGETARCH}/usr/bin/cilium-agent /usr/bin/cilium-agent-bin
COPY --from=debug-tools /go/bin/dlv /usr/bin/dlv
COPY --from=debug-tools /out/${TARGETOS}/${TARGETARCH}/bin/debug-wrapper /usr/bin/cilium-agent

# Copy the debug symbols across in case the binaries were stripped
COPY --from=builder /tmp/debug/${TARGETOS}/${TARGETARCH}/ /usr/lib/debug/

# Ensure dlv finds the debug symbols. Due to CGO_ENABLED=0, we have no GNU build-id, so Delve's default search path
# is insufficient.
RUN mkdir -p ${HOME}/.config/dlv && \
    echo 'debug-info-directories: ["/usr/lib/debug/.build-id","/usr/lib/debug"]' > ${HOME}/.config/dlv/config.yml
