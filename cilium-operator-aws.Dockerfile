# (first line comment needed for DOCKER_BUILDKIT use)
#
ARG BASE_IMAGE=scratch

# Cross-compile go, FROM comment must be located right before the FROM
# line for the parameter to be applied on BuildKit builds.
#
# FROM --platform=$BUILDPLATFORM
FROM docker.io/library/golang:1.15.7 as builder
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"

ADD . /go/src/github.com/cilium/cilium

WORKDIR /go/src/github.com/cilium/cilium/operator
ARG NOSTRIP
ARG LOCKDEBUG
ARG RACE
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
#
ARG TARGETARCH
RUN make GOARCH=$TARGETARCH NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG RACE=$RACE cilium-operator-aws
WORKDIR /go/src/github.com/cilium/cilium
RUN make GOARCH=$TARGETARCH licenses-all

FROM docker.io/library/alpine:3.13.1@sha256:08d6ca16c60fe7490c03d10dc339d9fd8ea67c6466dea8d558526b1330a85930 as certs
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
RUN apk --update add ca-certificates

FROM docker.io/library/golang:1.15.7 as gops
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
#
ARG TARGETARCH
RUN GOARCH=$TARGETARCH && [ "$GOARCH" != "arm64" ] || CC="aarch64-linux-gnu-gcc" && \
    go get -d github.com/google/gops && \
    cd /go/src/github.com/google/gops && \
    git checkout -b v0.3.14 v0.3.14 && \
    git --no-pager remote -v && \
    git --no-pager log -1 && \
    CGO_ENABLED=0 go install && \
    strip /go/bin/gops

FROM ${BASE_IMAGE}
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/operator/cilium-operator-aws /usr/bin/cilium-operator-aws
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=gops /go/bin/gops /bin/gops
COPY --from=builder /go/src/github.com/cilium/cilium/LICENSE.all /LICENSE.all
WORKDIR /
# FIXME Remove me once we add support for Go 1.16
ENV GODEBUG="madvdontneed=1"
CMD ["/usr/bin/cilium-operator-aws"]
