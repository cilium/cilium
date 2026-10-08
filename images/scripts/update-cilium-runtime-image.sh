#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

# Retrieve image from parameter and remove tag if one was provided, let make-image-tag in charge of creating the tag
image=${1}
image_dir=${2}
image="${image%%:*}"

image_tag="$(WITHOUT_SUFFIX=1 "${script_dir}/make-image-tag.sh" "${image_dir}")"

image_full="${image}:${image_tag}"
sha256=$("${script_dir}/get-image-digest.sh" "${image_full}" || echo "")
if [ -n "${sha256}" ]; then
  image_full="${image_full}@${sha256}"
fi

"${script_dir}/../../${image_dir}/update-cilium-runtime-image.sh" "${image_full}"
