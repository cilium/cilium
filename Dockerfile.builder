#
# Cilium build-time base image (image created from this file is used to build Cilium)
#
FROM docker.io/cilium/cilium-llvm:cae23fe2f43497ae268bd8ec186930bc5f32afac as cilium-llvm

FROM quay.io/cilium/cilium-runtime:2021-02-15@sha256:93f95a691deecc4c18eb029b5e04a0ad869320db15d75ca6376b4ed7d12d2b31
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium

#
# Env setup for Go (installed below)
#
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "$GOROOT/bin:$GOPATH/bin:$PATH"
ENV GO_VERSION 1.15.8

#
# Build dependencies
#
RUN \
    # add multi-arch support for both arm64 and amd64
    dpkg --add-architecture arm64 && dpkg --add-architecture amd64 && \
    # apt sources need to be limited to the native architecture
    ARCH=$(uname -m) && [ "$ARCH" != "aarch64" ] || ARCH="arm64" && [ "$ARCH" != "x86_64" ] || ARCH="amd64" && \
    sed "s/^deb http/deb [arch=$ARCH] http/" -i /etc/apt/sources.list && \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
      # Multi-arch cross-compilation packages, needed for CGO
      gcc-aarch64-linux-gnu \
      libc6-dev-arm64-cross \
      gcc-x86-64-linux-gnu \
      libc6-dev-amd64-cross \
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
COPY --from=cilium-llvm /usr/local/bin/llvm-objcopy /bin/

#
# Install Go
#
RUN ARCH=$(uname -m) && [ "$ARCH" != "aarch64" ] || ARCH="arm64" && [ "$ARCH" != "x86_64" ] || ARCH="amd64" && \
    curl -sfL https://dl.google.com/go/go${GO_VERSION}.linux-${ARCH}.tar.gz | tar -xzC /usr/local && \
    go clean -cache -modcache
