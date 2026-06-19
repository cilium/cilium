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

git clone https://github.com/containernetworking/plugins.git
cd plugins

git checkout -b "${cni_version}" "${cni_version}"
git --no-pager remote -v
git --no-pager log -1

mkdir -p "/out/cni"

export CGO_ENABLED=0

GOARCH="${TARGETARCH}" ./build_linux.sh -ldflags "-extldflags -static -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=${cni_version}"

cp bin/loopback /out/cni/loopback
strip /out/cni/loopback
