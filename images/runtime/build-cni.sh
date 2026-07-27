#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-releases depName=containernetworking/plugins
cni_version="v1.9.1"

mkdir -p /go/src/github.com/containernetworking
cd /go/src/github.com/containernetworking

curl -sSL https://github.com/containernetworking/plugins/archive/refs/tags/${cni_version}.tar.gz | tar xz
mv plugins-${cni_version#v} cni
cd cni

mkdir -p "/out/cni"
GOARCH="${TARGETARCH}" CGO_ENABLED=0 go build -o "/out/cni/loopback" \
    -ldflags "-s -w -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=${cni_version}" ./plugins/main/loopback

go version -m /out/cni/loopback | grep -q "GOARCH=$TARGETARCH" || (echo "Architecture mismatch: binary GOARCH does not match $TARGETARCH" && exit 1)
