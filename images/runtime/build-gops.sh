#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-releases depName=google/gops
gops_version="v0.3.27"

mkdir -p /go/src/github.com/google
cd /go/src/github.com/google

curl -sSL https://github.com/google/gops/archive/refs/tags/${gops_version}.tar.gz | tar xz
mv gops-${gops_version#v} gops
cd gops

mkdir -p "/out/usr/bin"
GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -ldflags "-s -w" -o "/out/usr/bin/gops" github.com/google/gops

go version -m /out/usr/bin/gops | grep -q "GOARCH=$TARGETARCH" || (echo "Architecture mismatch: binary GOARCH does not match $TARGETARCH" && exit 1)
