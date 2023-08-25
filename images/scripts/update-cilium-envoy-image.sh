#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

github_repo="cilium/proxy"
github_branch="main"
image="quay.io/cilium/cilium-envoy"

latest_commit_sha="$(curl -s https://api.github.com/repos/${github_repo}/commits/${github_branch} | jq -r --exit-status '.sha')"
envoy_version="$(curl -s https://raw.githubusercontent.com/${github_repo}/"${latest_commit_sha}"/ENVOY_VERSION)"

image_tag="${envoy_version//envoy-/v}-${latest_commit_sha}"

image_full="${image}:${image_tag}"
image_sha256=$("${script_dir}/get-image-digest.sh" "${image_full}" || echo "")
if [ -n "${image_sha256}" ]; then
  image_full="${image_full}@${image_sha256}"
fi

echo "Latest image from branch ${github_branch}: ${image_full}"

DOCKERFILEPATH="./images/cilium/Dockerfile"
echo "Updating image in ${DOCKERFILEPATH}"
sed -i -E "s|(FROM ${image}:)(.*)(@sha256:[0-9a-z]*)( as cilium-envoy)|\1${image_tag}@${image_sha256}\4|" ${DOCKERFILEPATH}

MAKEFILEPATH="./install/kubernetes/Makefile.values"
echo "Updating image in ${MAKEFILEPATH}"
sed -i -E "s|export[[:space:]]+CILIUM_ENVOY_VERSION:=.*|export CILIUM_ENVOY_VERSION:=${image_tag}|" ${MAKEFILEPATH}
sed -i -E "s|export[[:space:]]+CILIUM_ENVOY_DIGEST:=.*|export CILIUM_ENVOY_DIGEST:=${image_sha256}|" ${MAKEFILEPATH}

if git diff --exit-code ./install/kubernetes/Makefile.values ./images/cilium/Dockerfile &>/dev/null ; then
  echo "The envoy image is already up to date"
else
  echo "Updated the envoy image to be a latest version"
  echo "Please don't forget to execute 'make -C Documentation update-helm-values && make -C install/kubernetes'"
fi
