FROM golang:1.24 AS build

WORKDIR /cilium
COPY api api
COPY go.mod go.mod
COPY go.sum go.sum

WORKDIR /cilium/examples/datapath-plugin
COPY examples/datapath-plugin/go.mod \
     examples/datapath-plugin/go.sum \
     examples/datapath-plugin/*.go \
     examples/datapath-plugin/*.o \
     ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /datapath-plugin

FROM ubuntu:22.04 AS release

COPY --from=build /datapath-plugin /datapath-plugin

ENTRYPOINT ["/datapath-plugin"]

