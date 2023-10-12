#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=cilium/hubble
hubble_version="v0.12.2"

declare -A hubble_sha256
# renovate: datasource=github-release-attachments depName=cilium/hubble digestVersion=v0.12.2
hubble_sha256[amd64]="e0162f4c096a6435cf1e60712448bbaf91d10440b5da1fbb7bd9e711dacd3016"
# renovate: datasource=github-release-attachments depName=cilium/hubble digestVersion=v0.12.2
hubble_sha256[arm64]="921a23ade725e14c493cf1e9aeefdf185edaf57e487274fec848149375597e2c"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/cilium/hubble/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble
