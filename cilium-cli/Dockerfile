# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/golang:1.22.2-alpine3.19@sha256:cdc86d9f363e8786845bea2040312b4efa321b828acdeb26f393faa864d887b0 as builder
WORKDIR /go/src/github.com/cilium/cilium-cli
RUN apk add --no-cache git make ca-certificates
COPY . .
RUN make

FROM docker.io/library/busybox:stable-glibc@sha256:735f3e2573d5540476f997fbf562907d6901f995d6feb0e18132fade186f2230
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /go/src/github.com/cilium/cilium-cli/cilium /usr/local/bin/cilium
RUN ["wget", "-P", "/usr/local/bin", "https://dl.k8s.io/release/v1.23.6/bin/linux/amd64/kubectl"]
RUN ["chmod", "+x", "/usr/local/bin/kubectl"]
ENTRYPOINT []
