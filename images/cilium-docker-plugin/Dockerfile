# syntax=docker/dockerfile:1.6@sha256:ac85f380a63b13dfcefa89046420e1781752bab202122f8f50032edf31be0021

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE=scratch
ARG GOLANG_IMAGE=docker.io/library/golang:1.20.11@sha256:4e4a34f7940eddba81c1f6df88057411bb2d822df087c317f8532cc169f2725a

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG NOSTRIP
ARG NOOPT
ARG LOCKDEBUG
ARG RACE

WORKDIR /go/src/github.com/cilium/cilium/plugins/cilium-docker
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    make GOARCH=${TARGETARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} NOOPT=${NOOPT} LOCKDEBUG=${LOCKDEBUG} \
    && mkdir -p /out/${TARGETOS}/${TARGETARCH}/usr/bin && mv cilium-docker /out/${TARGETOS}/${TARGETARCH}/usr/bin

FROM ${BASE_IMAGE}
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/cilium-docker /usr/bin/cilium-docker
WORKDIR /
CMD ["/usr/bin/cilium-docker"]
