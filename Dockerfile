# (first line comment needed for DOCKER_BUILDKIT use)
#
# cilium-envoy from github.com/cilium/proxy
#
FROM quay.io/cilium/cilium-envoy:1177896bebde79915fe5f9092409bf0254084b4e@sha256:50fb77af2b3fa8a902bb11b26c97c2c230fba74bdb417a645bd938278a6f81df as cilium-envoy
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}

#
# Hubble CLI
#
FROM quay.io/cilium/hubble:v0.6.1@sha256:5155deebbf12546437978536d72ba2e87f093a542d979b42f4f95070f502cd73 as hubble
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}

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
FROM quay.io/cilium/cilium-builder:2021-01-20-v1.8@sha256:545a7837bc135a6f3193c791a0569a2897cf75a418b27e996a51c451cd245df6 as builder
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium
COPY . ./
ARG NOSTRIP
ARG LOCKDEBUG
ARG V
ARG LIBNETWORK_PLUGIN
#
# Please do not add any dependency updates before the 'make install' here,
# as that will mess with caching for incremental builds!
#
RUN make NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG PKG_BUILD=1 V=$V LIBNETWORK_PLUGIN=$LIBNETWORK_PLUGIN \
    SKIP_DOCS=true DESTDIR=/tmp/install clean-container build-container install-container

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
FROM quay.io/cilium/cilium-runtime:2021-02-03-v1.8@sha256:44c7e985ba0317726ae6960c3211456d9c076677cbad39439fcc16c81cdc813c
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
COPY --from=cilium-envoy / /
COPY --from=hubble /usr/bin/hubble /usr/bin/hubble
COPY --from=builder /go/src/github.com/cilium/cilium/plugins/cilium-cni/cni-install.sh /cni-install.sh
COPY --from=builder /go/src/github.com/cilium/cilium/plugins/cilium-cni/cni-uninstall.sh /cni-uninstall.sh
COPY --from=builder /go/src/github.com/cilium/cilium/contrib/packaging/docker/init-container.sh /init-container.sh
WORKDIR /home/cilium
RUN groupadd -f cilium \
    && echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc

ENV INITSYSTEM="SYSTEMD"
CMD ["/usr/bin/cilium"]
