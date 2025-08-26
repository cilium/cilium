#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

github_repo=${proxy_repo:-"cilium/proxy"}
github_branch=${proxy_branch:-"main"}

latest_commit_sha="$(curl -s https://api.github.com/repos/"${github_repo}"/commits/"${github_branch}" | jq -r --exit-status '.sha')"

repo="cilium-envoy"
image="quay.io/cilium/cilium-envoy"
filter="select(.name | test(\".*-.*-.*\"))"
if [ "${github_branch}" != "main" ] && ! [[ "${github_branch}" =~ ^v1\.[0-9]+$ ]]; then
    image="quay.io/cilium/cilium-envoy-dev"
    repo="cilium-envoy-dev"
    filter="select(.name)"
fi

# Filter all tags that are in the format of .*-.*-.* (e.g. v1.33.2-1742995211-ca0b42f0ecdf835224a8ddfc6fe0442368d4d766)
tags=$(curl -s "https://quay.io/api/v1/repository/cilium/${repo}/tag/?onlyActiveTags=true&filter_tag_name=like:${latest_commit_sha}" | jq -r ".tags[] | ${filter}")
image_tag=$(echo "${tags}" | jq -r .name)
image_sha256=$(echo "${tags}" | jq -r .manifest_digest)

image_full="${image}:${image_tag}@${image_sha256}"

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
