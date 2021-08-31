#!/bin/bash

# Copyright 2017-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# 938f6e2f7550e542bd78f3b9e8812665db109e02 == tag: cmd/protoc-gen-go-grpc/v1.1.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@938f6e2f7550e542bd78f3b9e8812665db109e02
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1
go install github.com/mitchellh/protoc-gen-go-json@v1.1.0
