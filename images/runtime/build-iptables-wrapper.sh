#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-releases depName=kubernetes-sigs/iptables-wrappers
iptables_wrappers_version="v3"

mkdir -p /go/src/github.com/kubernetes-sigs/iptables-wrappers
cd /go/src/github.com/kubernetes-sigs/iptables-wrappers

curl -sSL https://github.com/kubernetes-sigs/iptables-wrappers/archive/refs/tags/${iptables_wrappers_version}.tar.gz | tar xz --strip-components=1

# Build the iptables-wrapper binary. It is fully static (CGO disabled) and
# depends only on the iptables binaries present at runtime, so it can be dropped
# into the rootfs as-is.
mkdir -p "/out/usr/sbin"
GOARCH=${TARGETARCH} CGO_ENABLED=0 go build \
    -ldflags '-s -w -extldflags="-static" -buildid=""' \
    -trimpath \
    -o "/out/usr/sbin/iptables-wrapper" \
    github.com/kubernetes-sigs/iptables-wrappers
