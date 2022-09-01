#!/bin/bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

protoc_version="3.20.1"
arch=$(arch)
if [[ "${arch}" == "aarch64" ]]; then
  arch="aarch_64"
fi

curl --fail --show-error --silent --location \
  "https://github.com/protocolbuffers/protobuf/releases/download/v${protoc_version}/protoc-${protoc_version}-linux-${arch}.zip" \
    --output /tmp/protoc.zip

unzip /tmp/protoc.zip -x readme.txt -d /usr/local

# correct permissions for others
chmod o+rx /usr/local/bin/protoc
chmod o+rX -R /usr/local/include/google/
