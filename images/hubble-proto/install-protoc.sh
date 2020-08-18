#!/bin/bash

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

protoc_version="3.12.4"

curl --fail --show-error --silent --location \
  "https://github.com/protocolbuffers/protobuf/releases/download/v${protoc_version}/protoc-${protoc_version}-linux-x86_64.zip" \
    --output /tmp/protoc.zip

unzip /tmp/protoc.zip -x readme.txt -d /usr/local
rm -rf /tmp/protoc.zip

# correct permissions for others
chmod +rx /usr/local/bin/protoc
chmod +rX -R /usr/local/include/google/protobuf
