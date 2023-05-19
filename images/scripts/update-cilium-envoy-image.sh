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

latest_commit_sha="$(curl -s https://api.github.com/repos/${github_repo}/commits/${github_branch} | jq -r '.sha')"
envoy_version="$(curl -s https://raw.githubusercontent.com/${github_repo}/"${latest_commit_sha}"/ENVOY_VERSION)"

image_tag="${envoy_version//envoy-/v}-${latest_commit_sha}"

image_full="${image}:${image_tag}"
image_sha256=$("${script_dir}/get-image-digest.sh" "${image_full}" || echo "")
if [ -n "${image_sha256}" ]; then
  image_full="${image_full}@${image_sha256}"
fi

echo "Latest image from branch ${github_branch}: ${image_full}"

echo "Updating image in ./images/cilium/Dockerfile"
sed -i -E "s|(FROM ${image}:)(.*)(@sha256:[0-9a-z]*)( as cilium-envoy)|\1${image_tag}@${image_sha256}\4|" ./images/cilium/Dockerfile

echo "Updating image in ./install/kubernetes/cilium/values.yaml.tmpl"
# Using tr to workaround matching the multiline regex with sed
# yq would change formatting: https://github.com/mikefarah/yq/issues/465
# use of envoy.image.override (which would allow match in one line) isn't optimal either
< ./install/kubernetes/cilium/values.yaml.tmpl tr '\n' '\f' |
  sed -E "s|(# -- Envoy container image\..*tag: \")(v[0-9a-zA-Z\.-]*)(\")|\1${image_tag}\3|" |
  sed -E "s|(# -- Envoy container image\..*digest: \")(sha256:[0-9a-z]*)(\")|\1${image_sha256}\3|" |
  tr '\f' '\n' > ./install/kubernetes/cilium/values.yaml.tmpl_tmp &&
  mv ./install/kubernetes/cilium/values.yaml.tmpl_tmp ./install/kubernetes/cilium/values.yaml.tmpl

echo "Please don't forget to execute 'make -C Documentation update-helm-values && make -C install/kubernetes'"
