# syntax=docker/dockerfile:1.2

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/golang:1.19.2-alpine3.16@sha256:845f16d6c1c1501505a9f35978494bcd77a03f4f0cfeef56e3d8788325bea4a3 as builder
WORKDIR /go/src/github.com/cilium/cilium-cli
RUN apk add --no-cache git make
COPY . .
RUN make

FROM docker.io/library/busybox:stable-glibc@sha256:7b72c24a4a5750471d0a609d3d2de547a7816808d38ad93be5e7c747aa7742c5
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium-cli/cilium /usr/local/bin/cilium
RUN ["wget", "-P", "/usr/local/bin", "https://dl.k8s.io/release/v1.23.6/bin/linux/amd64/kubectl"]
RUN ["chmod", "+x", "/usr/local/bin/kubectl"]
ENTRYPOINT []
