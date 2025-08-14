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

curl --fail --show-error --silent --location "https://github.com/containernetworking/plugins/releases/download/v${cni_version}/cni-plugins-linux-${TARGETARCH}-v${cni_version}.tgz" --output "/tmp/cni-${TARGETARCH}.tgz"
printf "%s %s" "${cni_sha512[${TARGETARCH}]}" "/tmp/cni-${TARGETARCH}.tgz" | sha512sum -c
mkdir -p "/out/cni"
tar -C "/out/cni" -xf "/tmp/cni-${TARGETARCH}.tgz" ./loopback

strip /out/cni/loopback
