# syntax=docker/dockerfile:1.8@sha256:d6d396f3780b1dd56a3acbc975f57bd2fc501989b50164c41387c42d04e780d0

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

FROM docker.io/library/golang:1.22.4-alpine3.19@sha256:65b5d2d0a312fd9ef65551ad7f9cb5db1f209b7517ef6d5625cfd29248bc6c85 as builder
WORKDIR /go/src/github.com/cilium/cilium-cli
RUN apk add --no-cache git make ca-certificates
COPY . .
RUN make

FROM docker.io/library/busybox:stable-glibc@sha256:25e9fcbd3799fce9c0ec978303d35dbb18a6ffb1fc76fc9b181dd4e657e2cd13
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /go/src/github.com/cilium/cilium-cli/cilium /usr/local/bin/cilium
RUN ["wget", "-P", "/usr/local/bin", "https://dl.k8s.io/release/v1.23.6/bin/linux/amd64/kubectl"]
RUN ["chmod", "+x", "/usr/local/bin/kubectl"]
ENTRYPOINT []
