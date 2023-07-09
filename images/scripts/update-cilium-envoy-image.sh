#!/bin/bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

github_repo="cilium/proxy"
github_branch="v1.24"
image="quay.io/cilium/cilium-envoy"

latest_commit_sha="$(curl -s https://api.github.com/repos/${github_repo}/commits/${github_branch} | jq -r '.sha')"
envoy_version="${github_branch}"

image_tag="${envoy_version//envoy-/v}-${latest_commit_sha}"

image_full="${image}:${image_tag}"
image_sha256=$("${script_dir}/get-image-digest.sh" "${image_full}" || echo "")
if [ -n "${image_sha256}" ]; then
  image_full="${image_full}@${image_sha256}"
fi

echo "Latest image from branch ${github_branch}: ${image_full}"

echo "Updating image in ./images/cilium/Dockerfile"
sed -i -E "s|(FROM ${image}:)(.*)(@sha256:[0-9a-z]*)( as cilium-envoy)|\1${image_tag}@${image_sha256}\4|" ./images/cilium/Dockerfile
