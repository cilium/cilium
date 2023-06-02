#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

image="quay.io/cilium/cilium-envoy"
image_tag="$(yq '.envoy.image.tag' ./install/kubernetes/cilium/values.yaml.tmpl)"
image_sha256="$(yq '.envoy.image.digest' ./install/kubernetes/cilium/values.yaml.tmpl)"

sed -i -E "s|(FROM ${image}:)(.*)(@sha256:[0-9a-z]*)( as cilium-envoy)|\1${image_tag}@${image_sha256}\4|" ./images/cilium/Dockerfile

echo "Checking for different Cilium Envoy images"
git diff --exit-code ./images/cilium/Dockerfile
