# (first line comment needed for DOCKER_BUILDKIT use)
#
ARG BASE_IMAGE=scratch

FROM docker.io/library/golang:1.15.6 as builder
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"

ADD . /go/src/github.com/cilium/cilium

WORKDIR /go/src/github.com/cilium/cilium/operator
ARG NOSTRIP
ARG LOCKDEBUG
ARG RACE
RUN make NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG RACE=$RACE cilium-operator-azure
WORKDIR /go/src/github.com/cilium/cilium
RUN make licenses-all

FROM docker.io/library/alpine:3.12.0 as certs
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
RUN apk --update add ca-certificates

FROM docker.io/library/golang:1.15.6 as gops
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
RUN go get -d github.com/google/gops && \
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
COPY --from=builder /go/src/github.com/cilium/cilium/operator/cilium-operator-azure /usr/bin/cilium-operator-azure
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=gops /go/bin/gops /bin/gops
COPY --from=builder /go/src/github.com/cilium/cilium/LICENSE.all /LICENSE.all
WORKDIR /
CMD ["/usr/bin/cilium-operator-azure"]
