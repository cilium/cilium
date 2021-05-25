#!/bin/bash

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# FIXME: Update these versions once etcd-client 3.5 is released.
# These versions are pinned to support our older grpc-go 1.29 library,
# which required to build the version of the etcd client used in Cilium.
# See https://github.com/cilium/cilium/pull/13405#issuecomment-704766707
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@cee815d
go install github.com/golang/protobuf/protoc-gen-go@v1.4.3
go install github.com/mitchellh/protoc-gen-go-json@v1.0.0
