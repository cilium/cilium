#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

github_repo=${proxy_repo:-"cilium/proxy"}
github_branch=${proxy_branch:-"main"}

latest_commit_sha="$(curl -s https://api.github.com/repos/"${github_repo}"/commits/"${github_branch}" | jq -r --exit-status '.sha')"
envoy_version="$(curl -s https://raw.githubusercontent.com/"${github_repo}"/"${latest_commit_sha}"/ENVOY_VERSION)"

image="quay.io/cilium/cilium-envoy"
image_tag="${envoy_version//envoy-/v}-${latest_commit_sha}"
if [ "${github_branch}" != "main" ]; then
    image="quay.io/cilium/cilium-envoy-dev"
    image_tag="${latest_commit_sha}"
fi

image_full="${image}:${image_tag}"
image_sha256=$("${script_dir}/get-image-digest.sh" "${image_full}" || echo "")
if [ -n "${image_sha256}" ]; then
  image_full="${image_full}@${image_sha256}"
else
  echo "Digest is not (yet) available for image ${image_full}!"
  exit 1
fi

echo "Latest image from branch ${github_branch}: ${image_full}"

DOCKERFILEPATH="./images/cilium/Dockerfile"
echo "Updating image in ${DOCKERFILEPATH}"
sed -i -E "s|ARG CILIUM_ENVOY_IMAGE=quay.io/cilium/cilium-envoy.*:.*@sha256:[0-9a-z]*|ARG CILIUM_ENVOY_IMAGE=${image}:${image_tag}@${image_sha256}|" ${DOCKERFILEPATH}

MAKEFILEPATH="./install/kubernetes/Makefile.values"
echo "Updating image in ${MAKEFILEPATH}"
sed -i -E "s|export[[:space:]]+CILIUM_ENVOY_REPO:=.*|export CILIUM_ENVOY_REPO:=${image}|" ${MAKEFILEPATH}
sed -i -E "s|export[[:space:]]+CILIUM_ENVOY_VERSION:=.*|export CILIUM_ENVOY_VERSION:=${image_tag}|" ${MAKEFILEPATH}
sed -i -E "s|export[[:space:]]+CILIUM_ENVOY_DIGEST:=.*|export CILIUM_ENVOY_DIGEST:=${image_sha256}|" ${MAKEFILEPATH}

if git diff --exit-code ./install/kubernetes/Makefile.values ./images/cilium/Dockerfile &>/dev/null ; then
  echo "The envoy image is already up to date"
else
  echo "Updated the envoy image to be a latest version"
  echo "Please don't forget to execute 'make -C install/kubernetes && make -C Documentation update-helm-values'"
fi
