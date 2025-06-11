#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

iptables_wrapper_commit="06cad2ec6cb5ed0945b383fb185424c0a67f55eb"

mkdir -p /go/src/github.com/kubernetes-sigs
cd /go/src/github.com/kubernetes-sigs

git clone https://github.com/kubernetes-sigs/iptables-wrappers.git
cd iptables-wrappers

git checkout -b "$iptables_wrapper_commit"
git --no-pager remote -v
git --no-pager log -1

for arch in amd64 arm64; do
    mkdir -p "/out/linux/${arch}/bin"
    GOARCH="${arch}" CGO_ENABLED=0 go build -ldflags='-s -w -extldflags="-static" -buildid=""' -trimpath -o "/out/linux/${arch}/bin/iptables-wrapper" github.com/kubernetes-sigs/iptables-wrappers
done
