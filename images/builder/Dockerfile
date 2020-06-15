# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=docker.io/cilium/image-compilers:57f235db9a07e81c5b60c536498ecbf2501dd267@sha256:080245ac0d7d061e05613e6bf887dc3c8bb07392cd2ce265b8a4aaaad17f2125
ARG TESTER_IMAGE=docker.io/cilium/image-tester:70724309b859786e0a347605e407c5261f316eb0@sha256:89cc1f577d995021387871d3dbeb771b75ab4d70073d9bcbc42e532792719781
ARG GOLANG_IMAGE=docker.io/library/golang:1.14.4@sha256:d39a459086c75920390c9b9d42bbc7c52fef1fe7666e7633a02508c607c889d4

FROM ${GOLANG_IMAGE} as golang-dist

FROM ${COMPILERS_IMAGE} as rootfs
LABEL maintainer="maintainer@cilium.io"

COPY --from=golang-dist /usr/local/go /usr/local/go
RUN mkdir -p /go
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "${GOROOT}/bin:${GOPATH}/bin:${PATH}"

COPY build-go-deps.sh /tmp/build-go-deps.sh
RUN /tmp/build-go-deps.sh

COPY install-protoc.sh /tmp/install-protoc.sh
RUN /tmp/install-protoc.sh

FROM ${TESTER_IMAGE} as test
COPY --from=rootfs / /
COPY test /test
RUN /test/bin/cst

# this image is large, and re-using layers is beneficial,
# so final images is not squashed
FROM rootfs
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium
