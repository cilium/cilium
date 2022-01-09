FROM golang:1.17 as builder

ADD . /workspace

RUN CGO_ENABLED=0 go build -o /r2d2-server /workspace/server.go

FROM alpine
COPY --from=builder /r2d2-server /r2d2-server
