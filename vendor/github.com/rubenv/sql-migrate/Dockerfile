ARG GO_VERSION=1.20.6
ARG ALPINE_VERSION=3.12

### Vendor
FROM golang:${GO_VERSION} as vendor
COPY . /project
WORKDIR /project
RUN go mod tidy && go mod vendor

### Build binary
FROM golang:${GO_VERSION} as build-binary
COPY . /project
COPY --from=vendor /project/vendor /project/vendor
WORKDIR /project
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GO111MODULE=on go build \
    -v \
    -mod vendor \
    -o /project/bin/sql-migrate \
        /project/sql-migrate

### Image
FROM alpine:${ALPINE_VERSION} as image
COPY --from=build-binary /project/bin/sql-migrate /usr/local/bin/sql-migrate
RUN chmod +x /usr/local/bin/sql-migrate
ENTRYPOINT ["sql-migrate"]
