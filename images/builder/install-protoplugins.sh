#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# 8ba23be9613c672d40ae261d2a1335d639bdd59b == tag: cmd/protoc-gen-go-grpc/v1.3.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@8ba23be9613c672d40ae261d2a1335d639bdd59b
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.30.0
go install github.com/mitchellh/protoc-gen-go-json@v1.1.0
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1
