#
# cilium-envoy from github.com/cilium/proxy
#
FROM quay.io/cilium/cilium-envoy:9e1a3317863a5dd0e393fd168ce85cc2a3c709e4 as cilium-envoy

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
FROM quay.io/cilium/cilium-builder:2018-11-01 as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium
COPY . ./
ARG LOCKDEBUG
ARG V
#
# Please do not add any dependency updates before the 'make install' here,
# as that will mess with caching for incremental builds!
#
RUN make LOCKDEBUG=$LOCKDEBUG PKG_BUILD=1 V=$V SKIP_DOCS=true DESTDIR=/tmp/install clean-container build-container install-container

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
FROM quay.io/cilium/cilium-runtime:2018-11-29
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /tmp/install /
COPY --from=cilium-envoy / /
COPY plugins/cilium-cni/cni-install.sh /cni-install.sh
COPY plugins/cilium-cni/cni-uninstall.sh /cni-uninstall.sh
WORKDIR /root
RUN groupadd -f cilium \
	&& echo ". /etc/profile.d/bash_completion.sh" >> /root/.bashrc \
    && cilium completion bash >> /root/.bashrc \
    && sysctl -w kernel.core_pattern=/tmp/core.%e.%p.%t
ENV INITSYSTEM="SYSTEMD"
CMD ["/usr/bin/cilium"]
