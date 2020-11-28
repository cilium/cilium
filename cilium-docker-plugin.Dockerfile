# (first line comment needed for DOCKER_BUILDKIT use)
#
# Cross-compile go, FROM comment must right before the FROM line for
# the parameter to be applied on BuildKit builds.
#
# FROM --platform=$BUILDPLATFORM
FROM docker.io/library/golang:1.15.7 as builder
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
ADD . /go/src/github.com/cilium/cilium
WORKDIR /go/src/github.com/cilium/cilium/plugins/cilium-docker
ARG LOCKDEBUG
ARG RACE
ARG NOSTRIP
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
#
ARG TARGETARCH
RUN make GOARCH=$TARGETARCH NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG RACE=$RACE

FROM scratch
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/plugins/cilium-docker/cilium-docker /usr/bin/cilium-docker
WORKDIR /
CMD ["/usr/bin/cilium-docker"]
