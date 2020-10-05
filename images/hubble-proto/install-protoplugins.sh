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
# 938f6e2f7550e542bd78f3b9e8812665db109e02 == tag: cmd/protoc-gen-go-grpc/v1.1.0
go get google.golang.org/grpc/cmd/protoc-gen-go-grpc@938f6e2f7550e542bd78f3b9e8812665db109e02
go build google.golang.org/grpc/cmd/protoc-gen-go-grpc

# protoc-gen-go-json doesn't have releases, this is the latest commit at the time
go get github.com/mitchellh/protoc-gen-go-json@364b693
go build github.com/mitchellh/protoc-gen-go-json

go get google.golang.org/protobuf/cmd/protoc-gen-go@v1.25.0
go build google.golang.org/protobuf/cmd/protoc-gen-go
