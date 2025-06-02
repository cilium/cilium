# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# distroless images are signed by cosign and can be verified using:
# $ cosign verify $IMAGE_NAME --certificate-oidc-issuer https://accounts.google.com --certificate-identity keyless@distroless.iam.gserviceaccount.com
ARG BASE_IMAGE=gcr.io/distroless/static:nonroot@sha256:188ddfb9e497f861177352057cb21913d840ecae6c843d39e00d44fa64daa51c
# These SHA256 digests are important for two reasons:
# 1. They 'pin' the container image to a specific version. Unlike a tag that can be changed at any future point, a
#    SHA265 hash cannot be modified. This increases the security of the build by protecting against a class of supply
#    chain attacks where an attacker has write access to our 3rd party dependency image registries.
# 2. These digests must be to the *overall* digest, not the digest for a specific image. This is because the images will
#    be architecture specific, but the overall digest will contain all of the architectures.
ARG GOLANG_IMAGE=docker.io/library/golang:1.24.3@sha256:81bf5927dc91aefb42e2bc3a5abdbe9bb3bae8ba8b107e2a4cf43ce3402534c6
# We don't use ETCD_IMAGE because that's used in Makefile.defs to select a ETCD image approrpate for the *host platform*
# to run tests with.
ARG ETCD_SERVER_IMAGE=gcr.io/etcd-development/etcd:v3.6.0@sha256:2ebe4d4c6ad0458592d16806eb1711c4d30804e0f22b20cc5fbc24c19a8592e0

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
# MODIFIERS are extra arguments to be passed to make at build time.
ARG MODIFIERS

WORKDIR /go/src/github.com/cilium/cilium/clustermesh-apiserver
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    mkdir -p /out/${TARGETOS}/${TARGETARCH} && cp etcd-config.yaml /out/${TARGETOS}/${TARGETARCH}/etcd-config.yaml
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${TARGETARCH} $(echo $MODIFIERS | tr -d '"') \
    && mkdir -p /out/${TARGETOS}/${TARGETARCH}/usr/bin && mv clustermesh-apiserver /out/${TARGETOS}/${TARGETARCH}/usr/bin

WORKDIR /go/src/github.com/cilium/cilium
# licenses-all is a "script" that executes "go run" so its ARCH should be set
# to the same ARCH specified in the base image of this Docker stage (BUILDARCH)
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${BUILDARCH} licenses-all && mv LICENSE.all /out/${TARGETOS}/${TARGETARCH}

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS gops

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    ./build-gops.sh

FROM --platform=${TARGETARCH} ${ETCD_SERVER_IMAGE} AS etcd

FROM ${BASE_IMAGE} AS release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
COPY --from=gops /out/${TARGETOS}/${TARGETARCH}/bin/gops /bin/gops
# While the etcd image uses /usr/local/bin, we're moving it to /usr/bin to keep consistency with the rest of our images.
# We also don't grab the etcdctl or etcdutl binaries, as we don't need them for our application.
COPY --from=etcd /usr/local/bin/etcd /usr/bin/etcd
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/etcd-config.yaml /var/lib/cilium/etcd-config.yaml
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/clustermesh-apiserver /usr/bin/clustermesh-apiserver
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/LICENSE.all /LICENSE.all

# Configure gops to use a temporary directory, to prevent permission
# issues depending on the UID configured to run the entrypoint.
ENV GOPS_CONFIG_DIR=/tmp/gops

ENTRYPOINT ["/usr/bin/clustermesh-apiserver"]
