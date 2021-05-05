# syntax=docker/dockerfile:1.2

# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:be4c0e477c4c8a61b3a41f6e8a0bab1d686ccd4e@sha256:0b69c4c6b680b6827c98167837a96647fa7d710912f2a001053b6c3bb0d4d9ae

FROM ${CILIUM_BUILDER_IMAGE} as builder
WORKDIR /go/src/github.com/cilium/cilium-cli
COPY . .
RUN make

FROM docker.io/library/busybox:stable-glibc@sha256:95262195a281b3756e734b3996132030d76d5bd773564ea762d49eccf006571b
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium-cli/cilium /usr/local/bin/cilium
RUN ["wget", "-P", "/usr/local/bin", "https://dl.k8s.io/release/v1.21.0/bin/linux/amd64/kubectl"]
RUN ["chmod", "+x", "/usr/local/bin/kubectl"]
ENTRYPOINT []
