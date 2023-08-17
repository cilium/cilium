#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# 8ba23be9613c672d40ae261d2a1335d639bdd59b == tag: cmd/protoc-gen-go-grpc/v1.3.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@8ba23be9613c672d40ae261d2a1335d639bdd59b
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
go install github.com/mitchellh/protoc-gen-go-json@49905733154f04e47d685de62c2cc2b72613b69e
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1
go install github.com/protobuf-tools/protoc-gen-deepcopy@v0.0.3
