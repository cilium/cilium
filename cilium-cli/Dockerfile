# syntax=docker/dockerfile:1.2

# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM quay.io/cilium/cilium-builder:20ff0e6b01b9e5eeeedd6f334de80718a6b54835@sha256:9b38a14ca83ce1c081013974e082d37055523ca1d47543ba5be38b3575a6dc0f as builder
WORKDIR /go/src/github.com/cilium/cilium-cli
COPY . .
RUN make

FROM docker.io/library/busybox:stable-glibc@sha256:95262195a281b3756e734b3996132030d76d5bd773564ea762d49eccf006571b
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium-cli/cilium /usr/local/bin/cilium
RUN ["wget", "-P", "/usr/local/bin", "https://dl.k8s.io/release/v1.23.6/bin/linux/amd64/kubectl"]
RUN ["chmod", "+x", "/usr/local/bin/kubectl"]
ENTRYPOINT []
