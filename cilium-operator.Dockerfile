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
RUN make NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG EXTRA_GO_BUILD_FLAGS="-tags ipam_provider_aws,ipam_provider_azure,ipam_provider_operator"

FROM docker.io/library/alpine:3.9.3 as certs
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
RUN apk --update add ca-certificates

FROM scratch
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/operator/cilium-operator /usr/bin/cilium-operator
COPY --from=builder /go/src/github.com/cilium/cilium/operator/cilium-operator-generic /usr/bin/cilium-operator-generic
COPY --from=builder /go/src/github.com/cilium/cilium/operator/cilium-operator-aws /usr/bin/cilium-operator-aws
COPY --from=builder /go/src/github.com/cilium/cilium/operator/cilium-operator-azure /usr/bin/cilium-operator-azure

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
WORKDIR /
CMD ["/usr/bin/cilium-operator"]
