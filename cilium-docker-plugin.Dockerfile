FROM docker.io/library/golang:1.14.1 as builder
LABEL maintainer="maintainer@cilium.io"
ADD . /go/src/github.com/cilium/cilium
WORKDIR /go/src/github.com/cilium/cilium/plugins/cilium-docker
ARG LOCKDEBUG
RUN make LOCKDEBUG=$LOCKDEBUG

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/plugins/cilium-docker/cilium-docker /usr/bin/cilium-docker
WORKDIR /
CMD ["/usr/bin/cilium-docker"]
