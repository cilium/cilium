# (first line comment needed for DOCKER_BUILDKIT use)
#
FROM docker.io/library/golang:1.14.6 as builder
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"

ADD . /go/src/github.com/cilium/cilium

WORKDIR /go/src/github.com/cilium/cilium/operator
ARG NOSTRIP
ARG LOCKDEBUG
RUN make NOSTRIP=$NOSTRIP LOCKDEBUG=$LOCKDEBUG cilium-operator-azure

FROM docker.io/library/alpine:3.9.3 as certs
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
RUN apk --update add ca-certificates

FROM docker.io/library/golang:1.14.6 as gops
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
RUN go get -d github.com/google/gops && \
    cd /go/src/github.com/google/gops && \
    git checkout -b v0.3.6 v0.3.6 && \
    git --no-pager remote -v && \
    git --no-pager log -1 && \
    CGO_ENABLED=0 go install && \
    strip /go/bin/gops

FROM scratch
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/operator/cilium-operator-azure /usr/bin/cilium-operator-azure
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=gops /go/bin/gops /bin/gops
WORKDIR /
CMD ["/usr/bin/cilium-operator-azure"]
