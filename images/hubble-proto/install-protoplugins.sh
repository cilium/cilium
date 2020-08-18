#!/bin/bash

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

mkdir /proto
cd /proto

unset GOPATH

go mod init github.com/cilium/hubble/protoc

# latest tag at the time. For some reason `go get foo/bar/baz@vX.Y.Z` doesn't
# work with nested go.mod definitions.
go get google.golang.org/grpc/cmd/protoc-gen-go-grpc@cee815d
go build google.golang.org/grpc/cmd/protoc-gen-go-grpc

# protoc-gen-go-json doesn't have releases, this is the latest commit at the time
go get github.com/mitchellh/protoc-gen-go-json@8fbb6f3
go build github.com/mitchellh/protoc-gen-go-json

go get github.com/golang/protobuf@v1.4.2
go build github.com/golang/protobuf/protoc-gen-go
