FROM docker.io/library/golang:1.15.3-alpine3.12 as builder

RUN apk add --no-cache \
    curl \
    bash \
    make \
    && true

COPY install-protoplugins.sh /tmp/install-protoplugins.sh
RUN /tmp/install-protoplugins.sh

#------------------------------------------------------------------------------

FROM docker.io/library/alpine:3.12

RUN apk add --no-cache \
    curl \
    bash \
    make \
    && true

COPY install-glibc.sh /tmp/install-glibc.sh
RUN /tmp/install-glibc.sh

COPY install-protoc.sh /tmp/install-protoc.sh
RUN /tmp/install-protoc.sh

RUN mkdir /proto
COPY --from=builder /proto/protoc-gen-go /proto
COPY --from=builder /proto/protoc-gen-go-grpc /proto
COPY --from=builder /proto/protoc-gen-go-json /proto

COPY Makefile.docker /proto/Makefile

WORKDIR /source

CMD ["make", "-f", "/proto/Makefile"]
