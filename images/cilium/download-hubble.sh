#!/bin/bash

# Copyright 2017-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=cilium/hubble
hubble_version="v0.11.3"

declare -A hubble_sha256
# renovate: datasource=github-release-attachments depName=cilium/hubble digestVersion=v0.11.3
hubble_sha256[amd64]="cf1c699bd604cc5cb72219a36658b75ed6c112725c1a905f23f3b143b3bc4224"
# renovate: datasource=github-release-attachments depName=cilium/hubble digestVersion=v0.11.3
hubble_sha256[arm64]="f7a651f1ae2b6e3def04039c4fe644d6c291ef335e3c56227500921562e29232"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/cilium/hubble/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble
