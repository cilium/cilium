#
# Cilium build-time base image (image created from this file is used to build Cilium)
#
FROM quay.io/cilium/cilium-runtime:2020-11-13-v1.9@sha256:77f9e9dec1c34e46df92825a04e3029a6a08e722c10074de79134a181eed3eb8
LABEL maintainer="maintainer@cilium.io"
ARG ARCH=amd64
WORKDIR /go/src/github.com/cilium/cilium

#
# Env setup for Go (installed below)
#
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "$GOROOT/bin:$GOPATH/bin:$PATH"
ENV GO_VERSION 1.15.5

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
