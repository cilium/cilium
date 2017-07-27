FROM cilium:dependencies

LABEL "Maintainer: Andre Martins <andre@cilium.io>"

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

ADD plugins/cilium-cni/cni-install.sh /cni-install.sh
ADD plugins/cilium-cni/cni-uninstall.sh /cni-uninstall.sh

ENV PATH="/usr/local/clang+llvm/bin:$PATH"
ENV INITSYSTEM="SYSTEMD"

CMD ["/usr/bin/cilium"]
