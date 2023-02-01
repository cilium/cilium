#!/bin/bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-releases depName=cilium/hubble
hubble_version="v0.11.0"

declare -A hubble_sha256
# renovate: datasource=github-releases depName=cilium/hubble digestVersion=v0.11.0
hubble_sha256[amd64]="f6dcda9aec0d4a4647f6b640684f96a52aa86e8963c38ec2fd9cdf37c47f2a3d"
# renovate: datasource=github-releases depName=cilium/hubble digestVersion=v0.11.0
hubble_sha256[arm64]="62fc0032202a3dd7de62839c2735aed0c9ee3f42699bdb47ef2dcd1f018099f5"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/cilium/hubble/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble
