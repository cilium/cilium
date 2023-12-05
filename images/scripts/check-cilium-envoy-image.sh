#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

image="$(yq '.envoy.image.repository' ./install/kubernetes/cilium/values.yaml)"
image_tag="$(yq '.envoy.image.tag' ./install/kubernetes/cilium/values.yaml)"
image_sha256="$(yq '.envoy.image.digest' ./install/kubernetes/cilium/values.yaml)"

# pre-check for sed, in case that this script may fail to detect change when the `sed` command fails to replace the string and return code 0
image_regular="(ARG CILIUM_ENVOY_IMAGE=${image}:)(.*)(@sha256:[0-9a-z]*)"
grep -E "${image_regular}" ./images/cilium/Dockerfile &>/dev/null || exit 1
sed -i -E "s|${image_regular}|\1${image_tag}@${image_sha256}|" ./images/cilium/Dockerfile

echo "Checking for different Cilium Envoy images"
git diff --exit-code ./images/cilium/Dockerfile
