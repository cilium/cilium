FROM ubuntu:16.04

MAINTAINER "Andre Martins <andre@cilium.io>"

RUN apt-get update && \
apt-get install -y --no-install-recommends dh-golang devscripts fakeroot dh-make \
    build-essential curl gcc make libc6-dev.i386
RUN cd /tmp && \
curl -Sslk -o go1.7.1.linux-amd64.tar.gz \
https://storage.googleapis.com/golang/go1.7.1.linux-amd64.tar.gz && \
tar -C /usr/local -xzf go1.7.1.linux-amd64.tar.gz && \
rm -f go1.7.1.linux-amd64.tar.gz

ADD . /tmp/cilium-net-build/src/github.com/cilium/cilium

WORKDIR /tmp/cilium-net-build/src/github.com/cilium/cilium

RUN export DESTDIR="$PWD/debian/cilium" && \
export GOPATH=/tmp/cilium-net-build && \
export GOROOT=/usr/local/go && \
export PATH="$GOROOT/bin:$PATH" && \
export PKG_BUILD=1 && \
export VERSION="$(cat VERSION)" && \
./create-deb.sh