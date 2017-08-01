FROM cilium/dependencies:latest

ADD . /tmp/cilium-net-build/src/github.com/cilium/cilium

# cilium begin
RUN cd /tmp/cilium-net-build/src/github.com/cilium/cilium && \
export GOROOT=/usr/local/go && \
export GOPATH=/tmp/cilium-net-build && \
export PATH="$GOROOT/bin:/usr/local/clang+llvm/bin:$GOPATH/bin:$PATH" && \
make clean-container all && \
make PKG_BUILD=1 install && \
groupadd -f cilium

#cilium end
FROM ubuntu:16.04
ADD ./contrib/packaging/docker/clang-3.8.1.key /tmp/cilium-net-build/src/github.com/cilium/cilium/contrib/packaging/docker/clang-3.8.1.key
RUN apt-get update && \

apt-get install -y --no-install-recommends gcc make libelf-dev bison flex git ca-certificates libc6-dev.i386 iptables libgcc-5-dev binutils && \

# clang-3.8.1-begin
apt-get install -y --no-install-recommends curl xz-utils && \
cd /tmp && \
gpg --import /tmp/cilium-net-build/src/github.com/cilium/cilium/contrib/packaging/docker/clang-3.8.1.key && \
curl -Ssl -o clang+llvm.tar.xz \
http://releases.llvm.org/3.8.1/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz && \
curl -Ssl -o clang+llvm.tar.xz.sig \
http://releases.llvm.org/3.8.1/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz.sig && \
gpg --verify clang+llvm.tar.xz.sig && \
mkdir -p /usr/local && \
tar -C /usr/local -xJf ./clang+llvm.tar.xz && \
mv /usr/local/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04 /usr/local/clang+llvm && \
rm clang+llvm.tar.xz && \
rm -fr /usr/local/clang+llvm/include/llvm-c && \
rm -fr /usr/local/clang+llvm/include/clang-c && \
rm -fr /usr/local/clang+llvm/include/c++ && \
rm -fr /usr/local/clang+llvm/share && \
ls -d /usr/local/clang+llvm/lib/* | grep -vE clang$ | xargs rm -r && \
ls -d /usr/local/clang+llvm/bin/* | grep -vE "clang$|clang-3.8$|llc$" | xargs rm -r && \
# clang-3.8.1-end

# iproute2-begin
cd /tmp && \
git clone -b v4.10.0 git://git.kernel.org/pub/scm/linux/kernel/git/shemminger/iproute2.git && \
cd /tmp/iproute2 && \
./configure && \
make -j `getconf _NPROCESSORS_ONLN` && \
make install && \
# iproute2-end

# bpf-map-begin
curl -SsL https://github.com/cilium/bpf-map/releases/download/v1.0/bpf-map -o bpf-map && \
chmod +x bpf-map && \
mv bpf-map /usr/bin && \
# bpf-map-end

# cni-begin
# Include the loopback binary in the image
mkdir -p tmp && cd tmp && \
curl -sS -L https://storage.googleapis.com/kubernetes-release/network-plugins/cni-0799f5732f2a11b329d9e3d51b9c8f2e3759f2ff.tar.gz -o cni.tar.gz && \
tar -xvf cni.tar.gz && \
mkdir /cni && \
cp bin/loopback /cni && \
cd .. && \
rm -r tmp && \
# cni-end

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
