# (first line comment needed for DOCKER_BUILDKIT use)
#
FROM docker.io/library/golang:1.14.4 as builder
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
ADD . /go/src/github.com/cilium/cilium
WORKDIR /go/src/github.com/cilium/cilium/hubble-relay
ARG NOSTRIP
ARG LOCKDEBUG
RUN make NOSTRIP=${NOSTRIP} LOCKDEBUG=${LOCKDEBUG}

FROM docker.io/library/alpine:3.11 as certs
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
RUN apk --update add ca-certificates

FROM docker.io/library/golang:1.14.4 as gops
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
RUN go get -d github.com/google/gops && \
    cd /go/src/github.com/google/gops && \
    git checkout -b v0.3.10 v0.3.10 && \
    git --no-pager remote -v && \
    git --no-pager log -1 && \
    CGO_ENABLED=0 go install && \
    strip /go/bin/gops

FROM scratch
ARG CILIUM_SHA=""
LABEL cilium-sha=${CILIUM_SHA}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/hubble-relay/hubble-relay /usr/bin/hubble-relay
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=gops /go/bin/gops /bin/gops
ENTRYPOINT ["/usr/bin/hubble-relay"]
CMD ["serve"]
