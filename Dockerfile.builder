#
# Cilium build-time dependencies.
# Image created from this file is used to build Cilium.
#
FROM ubuntu:18.04

LABEL maintainer="maintainer@cilium.io"

WORKDIR /go/src/github.com/cilium/cilium

#
# Env setup for Go (installed below)
#
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "$GOROOT/bin:$GOPATH/bin:$PATH"
ENV GO_VERSION 1.11.1

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
		libc6-dev-i386 \
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
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#
# Install Go
#
RUN curl -sfL https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz | tar -xzC /usr/local \
	&& go get -u github.com/cilium/go-bindata/... \
	&& go get -u github.com/gordonklaus/ineffassign
