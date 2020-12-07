# (first line comment needed for DOCKER_BUILDKIT use)
#
FROM docker.io/library/golang:1.15.6 as builder
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
ADD . /go/src/github.com/cilium/cilium
WORKDIR /go/src/github.com/cilium/cilium/plugins/cilium-docker
ARG LOCKDEBUG
ARG RACE
ARG NOSTRIP
RUN make NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG RACE=$RACE

FROM scratch
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/plugins/cilium-docker/cilium-docker /usr/bin/cilium-docker
WORKDIR /
CMD ["/usr/bin/cilium-docker"]
