#!/bin/bash

# Copyright 2017-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-releases depName=cilium/hubble
hubble_version="v0.11.1"

declare -A hubble_sha256
# renovate: datasource=github-releases depName=cilium/hubble digestVersion=v0.11.1
hubble_sha256[amd64]="80dc54aaef4314de8ad64f5a95ae4d9067542defd69edd6a95574610a5c379bd"
# renovate: datasource=github-releases depName=cilium/hubble digestVersion=v0.11.1
hubble_sha256[arm64]="170c77a14099b636f162b12b6e63400648bf06e27aba973d3f511dcada84753e"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/cilium/hubble/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble
