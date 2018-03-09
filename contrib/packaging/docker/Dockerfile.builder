#
# Builder dependencies. This takes a long time to build from scratch!
# Also note that if build fails due to C++ internal error or similar,
# it is possible that the image build needs more RAM than available by
# default on non-Linux docker installs.
#
FROM ubuntu:17.10
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium/envoy
#
# Env setup for Go (installed below)
#
ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH="$GOROOT/bin:$GOPATH/bin:$PATH"
#
# Build dependencies
#
RUN \
apt-get update && \
#
# Install Go
#
apt-get install -y --no-install-recommends apt-utils curl git make ca-certificates && \
curl -Sslk -o /tmp/go.linux-amd64.tar.gz https://storage.googleapis.com/golang/go1.9.linux-amd64.tar.gz && \
tar -C /usr/local -xzf /tmp/go.linux-amd64.tar.gz && \
rm /tmp/go.linux-amd64.tar.gz && \
go get -u github.com/cilium/go-bindata/... && \
go get -u github.com/golang/protobuf/protoc-gen-go && \
go get -d github.com/lyft/protoc-gen-validate && \
(cd /go/src/github.com/lyft/protoc-gen-validate ; git checkout 930a67cf7ba41b9d9436ad7a1be70a5d5ff6e1fc ; make build) && \
#
# Install build requirements
#
apt-get -y install --no-install-recommends gcc binutils \
 pkg-config zip g++ zlib1g-dev unzip python wget rsync libtool cmake realpath m4 automake && \
apt-get clean
#
# Extract the needed Bazel version from the repo
#
ADD BAZEL_VERSION ./
#
# Install Bazel
#
RUN \
export BAZEL_VERSION=`cat BAZEL_VERSION` && \
wget https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh && \
chmod +x bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh && \
./bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh && \
mv /usr/local/bin/bazel /usr/bin && \
rm bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
#
# Add minimum Envoy files needed for the deps build. Touching any of these
# in the cilium repo will trigger this stage to be re-built.
#
ADD Makefile.deps WORKSPACE tools bazel ./
ADD BUILD_DEPS BUILD
RUN \
#
# Extract Envoy source version (git SHA) from WORKSPACE
#
grep "ENVOY_SHA[ \t]*=" WORKSPACE | cut -d \" -f 2 >SOURCE_VERSION && \
#
# Build only Envoy dependencies
#
make PKG_BUILD=1 -f Makefile.deps
#
# Absolutely nothing after making envoy deps!
#
