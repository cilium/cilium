FROM docker.io/library/golang:1.13.6 as builder
LABEL maintainer="maintainer@cilium.io"
ADD . /go/src/github.com/cilium/cilium
WORKDIR /go/src/github.com/cilium/cilium/plugins/cilium-docker
ARG LOCKDEBUG
ARG V
RUN make CGO_ENABLED=0 GOOS=linux LOCKDEBUG=$LOCKDEBUG PKG_BUILD=1 EXTRA_GOBUILD_FLAGS="-a -installsuffix cgo"
RUN strip cilium-docker

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/plugins/cilium-docker/cilium-docker /usr/bin/cilium-docker
WORKDIR /
CMD ["/usr/bin/cilium-docker"]
