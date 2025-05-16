#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-tags depName=grpc/grpc-go
GRPC_VERSION=cmd/protoc-gen-go-grpc/v1.5.1

GRPC_VERSION=${GRPC_VERSION#cmd/protoc-gen-go-grpc/}
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@${GRPC_VERSION}

# renovate: datasource=github-releases depName=protocolbuffers/protobuf-go
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
# renovate: datasource=github-releases depName=mfridman/protoc-gen-go-json
go install github.com/mfridman/protoc-gen-go-json@v1.5.0
# renovate: datasource=github-releases depName=pseudomuto/protoc-gen-doc
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1

BUF_BIN="buf"
# renovate: datasource=github-release-attachments depName=bufbuild/buf
BUF_VERSION=v1.54.0
BUF_VARIANT="Linux-$(uname --machine)"

curl --fail --show-error --silent --location \
    "https://github.com/bufbuild/buf/releases/download/${BUF_VERSION}/buf-${BUF_VARIANT}" \
    --output "${BUF_BIN}-${BUF_VARIANT}";

curl --fail --show-error --silent --location \
    "https://github.com/bufbuild/buf/releases/download/${BUF_VERSION}/sha256.txt" \
    --output sha256.txt
sha256sum --check --ignore-missing --status sha256.txt

mv "${BUF_BIN}-${BUF_VARIANT}" "/usr/local/bin/${BUF_BIN}";
chmod +rx "/usr/local/bin/${BUF_BIN}"