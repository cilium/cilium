# (first line comment needed for DOCKER_BUILDKIT use)
#
# cilium-envoy from github.com/cilium/proxy
#
FROM quay.io/cilium/cilium-envoy:e7430b113e09ee4fe900949af1f8e296e485269e@sha256:39e10fd3d353db56b5b719e0176cb74d64c1dda82211a252494650e2f013c253 as cilium-envoy
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}

#
# Hubble CLI
#
FROM quay.io/cilium/hubble:v0.7.1@sha256:cc76aa6394d613eaeeac0f15b72f50d426b3c47d4676557431661e6aa5e1597b as hubble
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
FROM quay.io/cilium/cilium-builder:2021-04-06-v1.9@sha256:912c251f4a4dbc868d00a965f6042f7ddc5a7acc47b50c42855e0c7988108e86 as builder
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium
COPY . ./
ARG NOSTRIP
ARG LOCKDEBUG
ARG RACE
ARG V
ARG LIBNETWORK_PLUGIN
#
# Please do not add any dependency updates before the 'make install' here,
# as that will mess with caching for incremental builds!
#
RUN make RACE=$RACE NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG PKG_BUILD=1 V=$V LIBNETWORK_PLUGIN=$LIBNETWORK_PLUGIN \
    SKIP_DOCS=true DESTDIR=/tmp/install build-container install-container \
    licenses-all

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
FROM quay.io/cilium/cilium-runtime:2021-04-06-v1.9@sha256:13bf1b7d1170e5f84c3a52797936c45b34cdcf6b7f2e5b51a8acf2da80047ed6
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
COPY --from=cilium-envoy / /
COPY --from=hubble /usr/bin/hubble /usr/bin/hubble
COPY --from=builder /go/src/github.com/cilium/cilium/plugins/cilium-cni/cni-install.sh /cni-install.sh
COPY --from=builder /go/src/github.com/cilium/cilium/plugins/cilium-cni/cni-uninstall.sh /cni-uninstall.sh
COPY --from=builder /go/src/github.com/cilium/cilium/contrib/packaging/docker/init-container.sh /init-container.sh
COPY --from=builder /go/src/github.com/cilium/cilium/LICENSE.all /LICENSE.all
WORKDIR /home/cilium
RUN groupadd -f cilium \
    && /usr/bin/hubble completion bash > /etc/bash_completion.d/hubble \
    && echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc

ENV INITSYSTEM="SYSTEMD"
# FIXME Remove me once we add support for Go 1.16
ENV GODEBUG="madvdontneed=1"
CMD ["/usr/bin/cilium"]
