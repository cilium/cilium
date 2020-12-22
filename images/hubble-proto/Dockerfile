# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG GOLANG_IMAGE=docker.io/library/golang:1.15.6-alpine3.12
ARG ALPINE_IMAGE=docker.io/library/alpine:3.12

FROM ${GOLANG_IMAGE} as builder

RUN apk add --no-cache \
  curl \
  bash \
  make \
  && true

COPY install-protoplugins.sh /tmp/install-protoplugins.sh
RUN /tmp/install-protoplugins.sh

#------------------------------------------------------------------------------

FROM ${ALPINE_IMAGE}

WORKDIR /proto

RUN apk add --no-cache \
  curl \
  bash \
  make \
  && true

COPY install-glibc.sh /tmp/install-glibc.sh
RUN /tmp/install-glibc.sh

COPY install-protoc.sh /tmp/install-protoc.sh
RUN /tmp/install-protoc.sh

COPY --from=builder /proto/protoc-gen-go .
COPY --from=builder /proto/protoc-gen-go-grpc .
COPY --from=builder /proto/protoc-gen-go-json .

COPY Makefile.docker ./Makefile

WORKDIR /source

CMD ["make", "-f", "/proto/Makefile"]
