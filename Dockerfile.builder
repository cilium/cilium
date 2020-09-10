#
# Cilium build-time base image (image created from this file is used to build Cilium)
#
FROM quay.io/cilium/cilium-runtime:2020-09-10@sha256:fa45d7a600a9b4baeee64f9c017898fe0eba5425ffac2ba5b3bafacc319544fa
LABEL maintainer="maintainer@cilium.io"
ARG ARCH=amd64
WORKDIR /go/src/github.com/cilium/cilium

#
# Env setup for Go (installed below)
#
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "$GOROOT/bin:$GOPATH/bin:$PATH"
ENV GO_VERSION 1.15.2

#
# Build dependencies
#
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
      # Base Cilium-build dependencies
      binutils \
      coreutils \
      curl \
      gcc \
      git \
      libc6-dev \
      libelf-dev \
      make && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#
# Install Go
#
RUN curl -sfL https://dl.google.com/go/go${GO_VERSION}.linux-${ARCH}.tar.gz | tar -xzC /usr/local && \
    go clean -cache -modcache
