#
# Cilium build-time dependencies.
# Image created from this file is used to build Cilium.
#
FROM docker.io/library/ubuntu:18.04

LABEL maintainer="maintainer@cilium.io"

WORKDIR /go/src/github.com/cilium/cilium

#
# Env setup for Go (installed below)
#
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "$GOROOT/bin:$GOPATH/bin:$PATH"
ENV GO_VERSION 1.13.6

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
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
	&& update-alternatives --install /usr/bin/clang clang /usr/bin/clang-7 100 \
	&& update-alternatives --install /usr/bin/llc llc /usr/bin/llc-7 100

#
# Install Go
#
RUN curl -sfL https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz | tar -xzC /usr/local && \
        go get -d -u github.com/gordonklaus/ineffassign && \
        cd /go/src/github.com/gordonklaus/ineffassign && \
        git checkout -b 1003c8bd00dc2869cb5ca5282e6ce33834fed514 1003c8bd00dc2869cb5ca5282e6ce33834fed514 && \
        go install && \
        go get -d github.com/cilium/go-bindata/... && \
        cd /go/src/github.com/cilium/go-bindata && \
        git checkout -b e950ad39c6092155a6d89f04c90b1c46d8c97d49 e950ad39c6092155a6d89f04c90b1c46d8c97d49 && \
        go install github.com/cilium/go-bindata/go-bindata
