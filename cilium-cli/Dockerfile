# syntax=docker/dockerfile:1.6@sha256:ac85f380a63b13dfcefa89046420e1781752bab202122f8f50032edf31be0021

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/golang:1.21.5-alpine3.18@sha256:9390a996e9f957842f07dff1e9661776702575dd888084e72d86eaa382ad56e3 as builder
WORKDIR /go/src/github.com/cilium/cilium-cli
RUN apk add --no-cache git make ca-certificates
COPY . .
RUN make

FROM docker.io/library/busybox:stable-glibc@sha256:ee22a5823b1d3e7881d168f50585274611dbe0ceed4d2ba5bc8afd7cfac71d23
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /go/src/github.com/cilium/cilium-cli/cilium /usr/local/bin/cilium
RUN ["wget", "-P", "/usr/local/bin", "https://dl.k8s.io/release/v1.23.6/bin/linux/amd64/kubectl"]
RUN ["chmod", "+x", "/usr/local/bin/kubectl"]
ENTRYPOINT []
