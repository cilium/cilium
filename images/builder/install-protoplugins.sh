#!/bin/bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# c285fc70e095eccc98d79b9a133e1e328141aefd == tag: cmd/protoc-gen-go-grpc/v1.2.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@c285fc70e095eccc98d79b9a133e1e328141aefd
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.0
go install github.com/mitchellh/protoc-gen-go-json@v1.1.0
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1
