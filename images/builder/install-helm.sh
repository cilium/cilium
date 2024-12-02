#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-tags depName=helm/helm
helm_version=v3.16.3

arch=$(arch)
if [[ "${arch}" == "aarch64" ]]; then
  arch="arm64"
fi


curl --fail --show-error --silent --location \
  "https://get.helm.sh/helm-${helm_version}-linux-${arch}.tar.gz" \
    --output /tmp/helm.tar.gz

tar -vxzf /tmp/helm.tar.gz --strip-components=1 -C /usr/local/bin/ "linux-${arch}/helm"
