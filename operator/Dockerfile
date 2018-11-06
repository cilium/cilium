FROM golang as builder
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium
COPY . ./
ARG LOCKDEBUG
ARG V
RUN make -C operator LOCKDEBUG=$LOCKDEBUG V=$V

FROM ubuntu:18.04
LABEL maintainer="maintainer@cilium.io"
WORKDIR /root
RUN groupadd -f cilium
COPY --from=builder /go/src/github.com/cilium/cilium/operator/cilium-operator /usr/bin/cilium-operator
CMD ["/usr/bin/cilium-operator"]
