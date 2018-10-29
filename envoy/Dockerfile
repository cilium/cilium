#
# Builder dependencies. This takes a long time to build from scratch!
# Also note that if build fails due to C++ internal error or similar,
# it is possible that the image build needs more RAM than available by
# default on non-Linux docker installs.
#
FROM ubuntu:18.04

LABEL maintainer="maintainer@cilium.io"

WORKDIR /go/src/github.com/cilium/cilium/envoy

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
		automake \
		binutils \
		ca-certificates \
		cmake \
		coreutils \
		curl \
		g++ \
		gcc \
		git \
		libelf-dev \
		libtool \
		m4 \
		make \
		ninja-build \
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
	&& go get -u github.com/golang/protobuf/protoc-gen-go \
	&& go get -d github.com/lyft/protoc-gen-validate \
	&& (cd /go/src/github.com/lyft/protoc-gen-validate ; git checkout 930a67cf7ba41b9d9436ad7a1be70a5d5ff6e1fc ; make build) \
	&& go get -u github.com/gordonklaus/ineffassign

#
# Extract the needed Bazel version from the repo
#
COPY BAZEL_VERSION ./
#
# Install Bazel
#
RUN export BAZEL_VERSION=`cat BAZEL_VERSION` \
	&& curl -sfL https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh -o bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh \
	&& chmod +x bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh \
	&& ./bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh \
	&& mv /usr/local/bin/bazel /usr/bin \
	&& rm bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh

#
# Add minimum Envoy files needed for the deps build. Touching any of these
# in the cilium repo will trigger this stage to be re-built.
#
COPY Makefile.deps WORKSPACE tools bazel ./
COPY BUILD_DEPS BUILD

RUN \
	# Extract Envoy source version (git SHA) from WORKSPACE
	grep "ENVOY_SHA[ \t]*=" WORKSPACE | cut -d \" -f 2 > SOURCE_VERSION \
	# Build only Envoy dependencies
	&& make PKG_BUILD=1 -f Makefile.deps

#
# Absolutely nothing after making envoy deps!
#
