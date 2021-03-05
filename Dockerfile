#
# cilium-envoy from github.com/cilium/proxy
#
FROM quay.io/cilium/cilium-envoy:e7430b113e09ee4fe900949af1f8e296e485269e@sha256:39e10fd3d353db56b5b719e0176cb74d64c1dda82211a252494650e2f013c253 as cilium-envoy

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
FROM quay.io/cilium/cilium-builder:2020-08-07-v1.7@sha256:957f7b80bf4c5d4f3d5ef5c6a8c42db7decc1f73d9e7f971b90456378c3aae58 as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium
COPY . ./
ARG LOCKDEBUG
ARG V
ARG LIBNETWORK_PLUGIN
#
# Please do not add any dependency updates before the 'make install' here,
# as that will mess with caching for incremental builds!
#
RUN make LOCKDEBUG=$LOCKDEBUG PKG_BUILD=1 V=$V LIBNETWORK_PLUGIN=$LIBNETWORK_PLUGIN \
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
FROM quay.io/cilium/cilium-runtime:2021-02-24-v1.7@sha256:804acd4b79c03fea879ea81d200050ab818d2a82e28f16beed9a8d5c1a1e97cb
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
COPY --from=cilium-envoy / /
COPY plugins/cilium-cni/cni-install.sh /cni-install.sh
COPY plugins/cilium-cni/cni-uninstall.sh /cni-uninstall.sh
COPY contrib/packaging/docker/init-container.sh /init-container.sh
WORKDIR /root
RUN groupadd -f cilium \
	&& echo ". /etc/profile.d/bash_completion.sh" >> /root/.bashrc \
    && cilium completion bash >> /root/.bashrc \
    && sysctl -w kernel.core_pattern=/tmp/core.%e.%p.%t
ENV INITSYSTEM="SYSTEMD"
CMD ["/usr/bin/cilium"]
