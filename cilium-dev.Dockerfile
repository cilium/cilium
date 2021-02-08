# This image tag should only be used for development when developers
# want to generate a docker image based on the binaries available in their
# development environmennt
FROM quay.io/cilium/cilium-envoy:63de0bd958d05d82e2396125dcf6286d92464c56 as cilium-envoy

FROM quay.io/cilium/cilium-runtime:2021-01-20@sha256:247eff116cc5d0b3a4931eabd67ea2e8679f7c12877729a73929d3f30753065b
LABEL maintainer="maintainer@cilium.io"
RUN apt-get update && apt-get install make -y
WORKDIR /go/src/github.com/cilium/cilium
ARG LOCKDEBUG
ARG V
ARG LIBNETWORK_PLUGIN
ARG RACE
COPY --from=cilium-envoy / /
COPY plugins/cilium-cni/cni-install.sh /cni-install.sh
COPY plugins/cilium-cni/cni-uninstall.sh /cni-uninstall.sh
COPY contrib/packaging/docker/init-container.sh /init-container.sh
COPY ./envoy ./envoy
COPY ./bpf ./bpf
COPY ./bugtool ./bugtool
COPY ./cilium-health ./cilium-health
COPY ./cilium ./cilium
COPY ./daemon ./daemon
COPY ./plugins/cilium-cni ./plugins/cilium-cni
COPY ./proxylib ./proxylib
COPY ./Makefile* ./
RUN for i in proxylib envoy plugins/cilium-cni bpf cilium daemon cilium-health bugtool; \
     do LOCKDEBUG=$LOCKDEBUG PKG_BUILD=1 V=$V LIBNETWORK_PLUGIN=$LIBNETWORK_PLUGIN \
            SKIP_DOCS=true DESTDIR= RACE=$RACE \
            make -C $i install; done
RUN groupadd -f cilium \
    && echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc
ENV INITSYSTEM="SYSTEMD"
CMD ["/usr/bin/cilium"]
