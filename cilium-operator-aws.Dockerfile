# (first line comment needed for DOCKER_BUILDKIT use)
#
FROM docker.io/library/golang:1.14.3 as builder
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"

ADD . /go/src/github.com/cilium/cilium

WORKDIR /go/src/github.com/cilium/cilium/operator
ARG NOSTRIP
ARG LOCKDEBUG
RUN make NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG cilium-operator-aws

FROM docker.io/library/alpine:3.9.3 as certs
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
RUN apk --update add ca-certificates

FROM scratch
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/operator/cilium-operator-aws /usr/bin/cilium-operator-aws
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
WORKDIR /
CMD ["/usr/bin/cilium-operator-aws"]
