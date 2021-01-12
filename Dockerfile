# (first line comment needed for DOCKER_BUILDKIT use)
#
# cilium-envoy from github.com/cilium/proxy
#
FROM quay.io/cilium/cilium-envoy:88c25901df85f53954f69300e3971bd547ed884b@sha256:da71e3f958795e4d25f2d74712fd7bd1ede621181c63bf804f69a916260a92ef as cilium-envoy
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
FROM quay.io/cilium/cilium-builder:2020-12-10@sha256:57012cdb87e43f3f6e50027a6a18381601a579ae081d6493460854cfa77f42b8 as builder
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
FROM quay.io/cilium/cilium-runtime:2021-01-12@sha256:58655346265fda806deacd2b82735e9866b39d9d241f2f4b1d45e63cacc45b57
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
CMD ["/usr/bin/cilium"]
