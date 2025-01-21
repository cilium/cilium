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

image="quay.io/cilium/cilium-runtime"

image_tag="$(WITHOUT_SUFFIX=1 "${script_dir}/make-image-tag.sh" images/runtime)"

image_full="${image}:${image_tag}"
sha256=$("${script_dir}/get-image-digest.sh" "${image_full}" || echo "")
if [ -n "${sha256}" ]; then
  image_full="${image_full}@${sha256}"
fi

"${script_dir}/../runtime/update-cilium-runtime-image.sh" "${image_full}"
