FROM ubuntu:16.04

MAINTAINER "Andre Martins <andre@cilium.io>"

ADD . /tmp/cilium-net-build/src/github.com/cilium/cilium

RUN apt-get update && \
apt-get install -y --no-install-recommends gcc make libelf-dev bison flex git libc6-dev.i386 && \
#
# clang-3.8.1-begin
apt-get install -y --no-install-recommends curl xz-utils && \
cd /tmp && \
curl -Ssl -o clang+llvm.tar.xz \
http://releases.llvm.org/3.8.1/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz && \
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
#
# iproute2-begin
cd /tmp && \
git clone -b v4.9.0 git://git.kernel.org/pub/scm/linux/kernel/git/shemminger/iproute2.git && \
cd /tmp/iproute2 && \
./configure && \
make -j `getconf _NPROCESSORS_ONLN` && \
make install && \
# iproute2-end
#
# cilium-begin

cd /tmp && \
curl -Sslk -o go.linux-amd64.tar.gz \
https://storage.googleapis.com/golang/go1.7.4.linux-amd64.tar.gz && \
tar -C /usr/local -xzf go.linux-amd64.tar.gz && \
cd /tmp/cilium-net-build/src/github.com/cilium/cilium && \
export GOROOT=/usr/local/go && \
export GOPATH=/tmp/cilium-net-build && \
export PATH="$GOROOT/bin:/usr/local/clang+llvm/bin:$PATH" && \
make && \
make PKG_BUILD=1 install && \
# cilium-end
#
apt-get purge --auto-remove -y gcc make bison flex git curl xz-utils && \
apt-get clean && \
rm -fr /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/local/go && \
echo '#!/usr/bin/env bash\ncp /opt/cni/bin/cilium-cni /tmp/cni/bin && /usr/bin/cilium $@' > /home/with-cni.sh && \
chmod +x /home/with-cni.sh

ENV PATH="/usr/local/clang+llvm/bin:$PATH"

CMD ["/usr/bin/cilium"]
