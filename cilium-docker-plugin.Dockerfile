FROM docker.io/library/golang:1.12.8 as builder
LABEL maintainer="maintainer@cilium.io"
ADD . /go/src/github.com/cilium/cilium
WORKDIR /go/src/github.com/cilium/cilium/plugins/cilium-docker
ARG LOCKDEBUG
ARG V
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o cilium-docker
RUN strip cilium-docker

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/plugins/cilium-docker/cilium-docker /usr/bin/cilium-docker
WORKDIR /
CMD ["/usr/bin/cilium-docker"]
