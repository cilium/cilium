# syntax=docker/dockerfile:1.6@sha256:ac85f380a63b13dfcefa89046420e1781752bab202122f8f50032edf31be0021

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/golang:1.21.4-alpine3.18@sha256:ff7d5e6e679675001a75f0fafa0f3383d50fc802e9f40fcd5e6bf3fcab5e1d15 as builder
WORKDIR /go/src/github.com/cilium/cilium-cli
RUN apk add --no-cache git make ca-certificates
COPY . .
RUN make

FROM docker.io/library/busybox:stable-glibc@sha256:7338d0c72c655d6534670ed72590cdc99afc9c559958c47eb3a5a17a7520a75c
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /go/src/github.com/cilium/cilium-cli/cilium /usr/local/bin/cilium
RUN ["wget", "-P", "/usr/local/bin", "https://dl.k8s.io/release/v1.23.6/bin/linux/amd64/kubectl"]
RUN ["chmod", "+x", "/usr/local/bin/kubectl"]
ENTRYPOINT []
