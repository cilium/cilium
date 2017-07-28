FROM cilium:dependencies

#LABEL "Maintainer: Andre Martins <andre@cilium.io>"

ADD . /tmp/cilium-net-build/src/github.com/cilium/cilium

# cilium-begin

RUN cd /tmp/cilium-net-build/src/github.com/cilium/cilium && \
export GOROOT=/usr/local/go && \
export GOPATH=/tmp/cilium-net-build && \
export PATH="$GOROOT/bin:/usr/local/clang+llvm/bin:$GOPATH/bin:$PATH" && \
make clean-container all && \
make PKG_BUILD=1 install && \
groupadd -f cilium && \
# cilium-end
#
apt-get purge --auto-remove -y gcc make bison flex git curl xz-utils ca-certificates && \
# Needed for system minimal requirements checkers
apt-get clean && \
rm -fr /root /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/local/go

FROM ubuntu:16.04

ADD ./contrib/packaging/docker/clang-3.8.1.key /tmp/clang-3.8.1.key

#### add Dockerfile.deps here

cp bin/loopback /cni && \
cd .. && \
rm -r tmp && \
# cni-end

#### end adding Dockerfile.deps here


# cilium-begin

groupadd -f cilium && \

# cilium-end

apt-get purge --auto-remove -y gcc make bison flex git curl xz-utils ca-certificates && \
# Needed for system minimal requirements checkers
apt-get clean && \
rm -fr /root /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD plugins/cilium-cni/cni-install.sh /cni-install.sh
ADD plugins/cilium-cni/cni-uninstall.sh /cni-uninstall.sh

ENV PATH="/usr/local/clang+llvm/bin:$PATH"
ENV INITSYSTEM="SYSTEMD"

COPY --from=0 /usr/bin/cilium /usr/bin/cilium
COPY --from=0 /usr/bin/cilium-docker /usr/bin/cilium-docker
COPY --from=0 /usr/bin/cilium-agent /usr/bin/cilium-agent
COPY --from=0 /opt/cni/bin/cilium-cni /opt/cni/bin/cilium-cni
COPY --from=0 /etc/cni/net.d/10-cilium-cni.conf /etc/cni/net.d/10-cilium-cni.conf
COPY --from=0 /etc/bash_completion.d/cilium /etc/bash_completion.d/cilium

CMD ["/usr/bin/cilium"]
