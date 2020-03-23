#
# Cilium build-time base image (image created from this file is used to build Cilium)
#
FROM quay.io/cilium/cilium-runtime:2020-03-23
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium

#
# Env setup for Go (installed below)
#
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "$GOROOT/bin:$GOPATH/bin:$PATH"
ENV GO_VERSION 1.14.1

#
# Build dependencies
#
RUN \
apt-get update && \
apt-get upgrade -y --no-install-recommends && \
apt-get install -y --no-install-recommends \
# Base Cilium-build dependencies
  apt-utils \
  binutils \
  coreutils \
  curl \
  gcc \
  git \
  libc6-dev \
  libc6-dev-i386 \
  libelf-dev \
  m4 \
  make \
  pkg-config \
  python \
  rsync \
  unzip \
  wget \
  zip \
  zlib1g-dev && \
apt-get purge --auto-remove && \
apt-get clean && \
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#
# Install Go
#
RUN \
curl -sfL https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz | tar -xzC /usr/local && \
go get -d -u github.com/gordonklaus/ineffassign && \
cd /go/src/github.com/gordonklaus/ineffassign && \
git checkout -b 1003c8bd00dc2869cb5ca5282e6ce33834fed514 1003c8bd00dc2869cb5ca5282e6ce33834fed514 && \
go install
