FROM fedora:24

MAINTAINER "Andre Martins <andre@cilium.io>"

RUN dnf install -y gettext curl gcc fedora-packager fedora-review && \
cd /tmp && \
curl -Sslk -o go1.7.1.linux-amd64.tar.gz \
https://storage.googleapis.com/golang/go1.7.1.linux-amd64.tar.gz && \
tar -C /usr/local -xzf go1.7.1.linux-amd64.tar.gz && \
rm -f go1.7.1.linux-amd64.tar.gz

ADD . /tmp/cilium-net-build/src/github.com/cilium/cilium

WORKDIR /tmp/cilium-net-build/src/github.com/cilium/cilium

RUN rpmdev-setuptree && \
export VERSION_PATH="cilium_$(cat VERSION)" && \
export DESTDIR="~/rpmbuild/" && \
export GOPATH=/tmp/cilium-net-build && \
export GOROOT=/usr/local/go && \
export PATH="$GOROOT/bin:$PATH" && \
export PKG_BUILD=1 && \
export VERSION="$(cat VERSION)" && \
./create-rpm.sh
