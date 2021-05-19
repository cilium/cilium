#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

image="quay.io/cilium/cilium-builder"

image_tag="$(WITHOUT_SUFFIX=1 "${script_dir}/make-image-tag.sh" images/builder)"

image_full="${image}:${image_tag}"
sha256=$("${script_dir}/get-image-digest.sh" "${image_full}" || echo "")
if [ -n "${sha256}" ]; then
  image_full="${image_full}@${sha256}"
fi

# shellcheck disable=SC2207
used_by=($(git grep -l CILIUM_BUILDER_IMAGE= images/*/Dockerfile) "test/k8sT/manifests/demo-customcalls.yaml")

for i in "${used_by[@]}" ; do
  sed -E "s#(CILIUM_BUILDER_IMAGE=|image: )${image}:.*\$#\1${image_full}#" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

do_check="${CHECK:-false}"
if [ "${do_check}" = "true" ] ; then
    git diff --exit-code "${used_by[@]}"
fi
