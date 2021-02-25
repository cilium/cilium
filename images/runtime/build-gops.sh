#!/bin/bash

# Copyright 2017-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

gops_version="v0.3.17"

mkdir -p /go/src/github.com/google
cd /go/src/github.com/google

git clone https://github.com/google/gops.git
cd gops

git checkout -b "${gops_version}" "${gops_version}"
git --no-pager remote -v
git --no-pager log -1

for arch in amd64 arm64 ; do
  mkdir -p "/out/linux/${arch}/bin"
  GOARCH="${arch}" go build -ldflags "-s -w" -o "/out/linux/${arch}/bin/gops" github.com/google/gops
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/gops
aarch64-linux-gnu-strip /out/linux/arm64/bin/gops
