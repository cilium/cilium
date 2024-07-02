#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

MAKEFILEPATH="./install/kubernetes/Makefile.values"

image=$(grep -oP 'CILIUM_ENVOY_REPO:=\K.*' ${MAKEFILEPATH})
image_tag=$(grep -oP 'CILIUM_ENVOY_VERSION:=\K.*' ${MAKEFILEPATH})
image_sha256=$(grep -oP 'CILIUM_ENVOY_DIGEST:=\K.*' ${MAKEFILEPATH})

DOCKERFILEPATH="./images/cilium/Dockerfile"
echo "Updating image in ${DOCKERFILEPATH} with ${image}:${image_tag}@${image_sha256}"
sed -i -E "s|ARG CILIUM_ENVOY_IMAGE=quay.io/cilium/cilium-envoy.*:.*@sha256:[0-9a-z]*|ARG CILIUM_ENVOY_IMAGE=${image}:${image_tag}@${image_sha256}|" ${DOCKERFILEPATH}
