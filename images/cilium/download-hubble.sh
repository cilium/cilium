#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=cilium/hubble
hubble_version="v0.11.6"

declare -A hubble_sha256
# renovate: datasource=github-release-attachments depName=cilium/hubble digestVersion=v0.11.6
hubble_sha256[amd64]="2d2768574351a85770088c9239214cf50cb42461979f116ef20f985eb943b05a"
# renovate: datasource=github-release-attachments depName=cilium/hubble digestVersion=v0.11.6
hubble_sha256[arm64]="6c74e702638533ae835110be59d303ee74d4a19498bdb83ad488025684276ffe"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/cilium/hubble/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble
