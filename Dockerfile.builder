#
# Cilium build-time base image (image created from this file is used to build Cilium)
FROM docker.io/cilium/cilium-llvm:33c302266cecc264febfca95129ce8dad9397c81 as cilium-llvm

FROM quay.io/cilium/cilium-runtime:2021-02-15-v1.8@sha256:0e1b542624918b2c6b775d21c9dce448a14dc789d66c7afe2012c21c9ec6c18e
LABEL maintainer="maintainer@cilium.io"
ARG ARCH=amd64
WORKDIR /go/src/github.com/cilium/cilium

#
# Env setup for Go (installed below)
#
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "$GOROOT/bin:$GOPATH/bin:$PATH"
ENV GO_VERSION 1.14.15

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
# Retrieve llvm-objcopy binary
#
COPY --from=cilium-llvm /bin/llvm-objcopy /bin/

#
# Install Go
#
RUN curl -sfL https://dl.google.com/go/go${GO_VERSION}.linux-${ARCH}.tar.gz | tar -xzC /usr/local && \
    GO111MODULE=on go get github.com/gordonklaus/ineffassign@1003c8bd00dc2869cb5ca5282e6ce33834fed514 && \
    go clean -cache -modcache
