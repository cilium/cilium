#
# Cilium build-time base image (image created from this file is used to build Cilium)
#
FROM docker.io/cilium/cilium-llvm:cae23fe2f43497ae268bd8ec186930bc5f32afac as cilium-llvm

FROM quay.io/cilium/cilium-runtime:2020-12-10@sha256:ee6f0f81fa73125234466c13fd16bed30cc3209daa2f57098f63e0285779e5f3
LABEL maintainer="maintainer@cilium.io"
ARG ARCH=amd64
WORKDIR /go/src/github.com/cilium/cilium

#
# Env setup for Go (installed below)
#
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "$GOROOT/bin:$GOPATH/bin:$PATH"
ENV GO_VERSION 1.15.6

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
COPY --from=cilium-llvm /usr/local/bin/llvm-objcopy /bin/

#
# Install Go
#
RUN curl -sfL https://dl.google.com/go/go${GO_VERSION}.linux-${ARCH}.tar.gz | tar -xzC /usr/local && \
    go clean -cache -modcache
