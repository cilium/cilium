#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=protocolbuffers/protobuf
protoc_version="v28.1"
protoc_ersion="${protoc_version//v/}"
arch=$(arch)
if [[ "${arch}" == "aarch64" ]]; then
  arch="aarch_64"
fi

curl --fail --show-error --silent --location \
  "https://github.com/protocolbuffers/protobuf/releases/download/${protoc_version}/protoc-${protoc_ersion}-linux-${arch}.zip" \
    --output /tmp/protoc.zip

unzip /tmp/protoc.zip -x readme.txt -d /usr/local

# correct permissions for others
chmod o+rx /usr/local/bin/protoc
chmod o+rX -R /usr/local/include/google/
