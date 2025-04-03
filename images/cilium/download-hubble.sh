#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=cilium/hubble
hubble_version="v1.17.2"

declare -A hubble_sha256
# renovate: datasource=github-release-attachments depName=cilium/hubble digestVersion=v1.17.2
hubble_sha256[amd64]="b048e73ee39ce1a46730460362afb14e08cf9edf2c541ab9dd8f2aadcb350ddc"
# renovate: datasource=github-release-attachments depName=cilium/hubble digestVersion=v1.17.2
hubble_sha256[arm64]="0d2252b80ef5bb956dc8ae86c9a96b45ed85200b2818cbd69249a5a3a3b33e40"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/cilium/hubble/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble
