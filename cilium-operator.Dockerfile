FROM docker.io/library/golang:1.11.1 as builder
LABEL maintainer="maintainer@cilium.io"
ADD . /go/src/github.com/cilium/cilium
WORKDIR /go/src/github.com/cilium/cilium/operator
ARG LOCKDEBUG
ARG V
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o cilium-operator
RUN strip cilium-operator

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/operator/cilium-operator /usr/bin/cilium-operator
WORKDIR /
CMD ["/usr/bin/cilium-etcd-operator"]
