#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cni-version.sh
source "${script_dir}/cni-version.sh"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/containernetworking/plugins/releases/download/v${cni_version}/cni-plugins-linux-${arch}-v${cni_version}.tgz" --output "/tmp/cni-${arch}.tgz"
  printf "%s %s" "${cni_sha512[${arch}]}" "/tmp/cni-${arch}.tgz" | sha512sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/cni-${arch}.tgz" ./loopback
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/loopback
aarch64-linux-gnu-strip /out/linux/arm64/bin/loopback
