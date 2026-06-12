#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-releases depName=kubernetes/kubernetes
kubectl_version="v1.35.3"
# renovate: datasource=github-releases depName=helm/helm
helm_version="v3.17.3"
# renovate: datasource=github-releases depName=mikefarah/yq
yq_version="v4.45.1"

ARCH=$(uname -m)
case "${ARCH}" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: ${ARCH}"; exit 1 ;;
esac

curl --fail --show-error --silent --location \
  "https://dl.k8s.io/release/${kubectl_version}/bin/linux/${ARCH}/kubectl" \
  --output /usr/local/bin/kubectl
chmod +x /usr/local/bin/kubectl

curl --fail --show-error --silent --location \
  "https://get.helm.sh/helm-${helm_version}-linux-${ARCH}.tar.gz" | \
  tar xz --strip-components=1 -C /usr/local/bin "linux-${ARCH}/helm"

curl --fail --show-error --silent --location \
  "https://github.com/mikefarah/yq/releases/download/${yq_version}/yq_linux_${ARCH}" \
  --output /usr/local/bin/yq
chmod +x /usr/local/bin/yq
