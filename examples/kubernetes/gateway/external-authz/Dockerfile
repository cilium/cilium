FROM docker.io/library/golang:1.26 AS builder

WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -o /out/external-authz ./examples/kubernetes/gateway/external-authz

FROM cgr.dev/chainguard/static:latest
COPY --from=builder /out/external-authz /usr/local/bin/external-authz
ENTRYPOINT ["/usr/local/bin/external-authz"]
