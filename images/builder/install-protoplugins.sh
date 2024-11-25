#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-releases depName=grpc/grpc-go
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@1adbea267b837660726952ed6711b348dee87aa5
# renovate: datasource=github-releases depName=protocolbuffers/protobuf-go
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.35.2
# renovate: datasource=github-releases depName=mfridman/protoc-gen-go-json
go install github.com/mfridman/protoc-gen-go-json@v1.4.1
# renovate: datasource=github-releases depName=pseudomuto/protoc-gen-doc
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1
