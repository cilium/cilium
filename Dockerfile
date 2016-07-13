FROM ubuntu:15.10

MAINTAINER "Andre Martins <andre@cilium.io>"

ADD . /tmp/cilium-net-build/src/github.com/noironetworks/cilium-net

RUN apt-get update && \
apt-get install -y --no-install-recommends gcc make libelf-dev bison flex git libc6-dev.i386 && \
#
# clang-3.7-begin
apt-get install -y --no-install-recommends curl xz-utils && \
cd /tmp && \
curl -Ssl -o clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-15.10.tar.xz \
http://llvm.org/releases/3.7.1/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-15.10.tar.xz && \
mkdir -p /usr/local && \
tar -C /usr/local -xJf ./clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-15.10.tar.xz && \
rm clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-15.10.tar.xz && \
#rm -fr /usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-15.10/lib
#rm -fr /usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-15.10/include
#rm -fr /usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-15.10/share
#cd /usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-15.10/bin && \
#ls | grep -Ev "clang|clang-3.7" | xargs rm && \
# clang-3.7-end
#
# iproute2-begin
cd /tmp && \
git clone git://git.breakpoint.cc/dborkman/iproute2.git && \
cd /tmp/iproute2 && \
git checkout bpf-wip && \
./configure && \
make -j `getconf _NPROCESSORS_ONLN` && \
make install && \
# iproute2-end
#
# cilium-begin
cd /tmp && \
curl -Sslk -o go1.6.2.linux-amd64.tar.gz \
https://storage.googleapis.com/golang/go1.6.2.linux-amd64.tar.gz && \
tar -C /usr/local -xzf go1.6.2.linux-amd64.tar.gz && \
cd /tmp/cilium-net-build/src/github.com/noironetworks/cilium-net && \
export GOROOT=/usr/local/go && \
export GOPATH=/tmp/cilium-net-build && \
export PATH="$GOROOT/bin:$PATH" && \
make cilium && \
make install cilium && \
rm -fr /usr/lib/cilium/map_ctrl && \
# cilium-end
#
apt-get purge --auto-remove -y gcc make bison flex git curl xz-utils && \
apt-get clean && \
rm -fr /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/local/go

ENV PATH="/usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-15.10/bin:$PATH"

CMD ["/usr/bin/cilium"]
