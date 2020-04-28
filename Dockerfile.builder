#
# Cilium build-time dependencies.
# Image created from this file is used to build Cilium.
#
FROM docker.io/library/ubuntu:20.04

LABEL maintainer="maintainer@cilium.io"

ARG ARCH=amd64

WORKDIR /go/src/github.com/cilium/cilium

#
# Env setup for Go (installed below)
#
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "$GOROOT/bin:$GOPATH/bin:$PATH"
ENV GO_VERSION 1.14.2

#
# Build dependencies
#
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		apt-utils \
		binutils \
		ca-certificates \
		clang-7 \
		coreutils \
		curl \
		gcc \
		git \
		iproute2 \
		libc6-dev \
		libelf-dev \
		llvm-7 \
		m4 \
		make \
		pkg-config \
		python \
		rsync \
		unzip \
		wget \
		zip \
		zlib1g-dev \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
	&& update-alternatives --install /usr/bin/clang clang /usr/bin/clang-7 100 \
	&& update-alternatives --install /usr/bin/llc llc /usr/bin/llc-7 100

#
# Install Go
#
RUN curl -sfL https://dl.google.com/go/go${GO_VERSION}.linux-${ARCH}.tar.gz | tar -xzC /usr/local && \
        GO111MODULE=on go get github.com/gordonklaus/ineffassign@1003c8bd00dc2869cb5ca5282e6ce33834fed514 && \
        go clean -cache -modcache
