#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-tags depName=kubernetes-sigs/iptables-wrappers
IPTABLES_WRAPPERS_VERSION=iptables-wrapper-v4

# Build the iptables-wrapper binary. It is fully static (CGO disabled) and
# depends only on the iptables binaries present at runtime, so it can be dropped
# into the rootfs as-is.
GOBIN=/out/usr/sbin GOARCH=${TARGETARCH} CGO_ENABLED=0 go install \
    -ldflags '-s -w -extldflags="-static" -buildid=""' \
    -trimpath \
    sigs.k8s.io/iptables-wrappers/cmd/iptables-wrapper@${IPTABLES_WRAPPERS_VERSION}

go version -m /out/usr/sbin/iptables-wrapper | grep -q "GOARCH=$TARGETARCH" || (echo "Architecture mismatch: binary GOARCH does not match $TARGETARCH" && exit 1)
