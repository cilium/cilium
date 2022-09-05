# syntax=docker/dockerfile:1.2

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM quay.io/cilium/cilium-builder:20ff0e6b01b9e5eeeedd6f334de80718a6b54835@sha256:9b38a14ca83ce1c081013974e082d37055523ca1d47543ba5be38b3575a6dc0f as builder
WORKDIR /go/src/github.com/cilium/cilium-cli
COPY . .
RUN make

FROM docker.io/library/busybox:stable-glibc@sha256:306a4bb878f85e8cc22bdd1e9431f1526e208bad5112cd09f04178a6a34c7f11
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium-cli/cilium /usr/local/bin/cilium
RUN ["wget", "-P", "/usr/local/bin", "https://dl.k8s.io/release/v1.23.6/bin/linux/amd64/kubectl"]
RUN ["chmod", "+x", "/usr/local/bin/kubectl"]
ENTRYPOINT []
