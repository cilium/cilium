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

image="quay.io/cilium/cilium-runtime"

image_tag="$(WITHOUT_SUFFIX=1 "${script_dir}/make-image-tag.sh" images/runtime)"

# shellcheck disable=SC2207
used_by=($(git grep -l CILIUM_RUNTIME_IMAGE= images/*/Dockerfile))

for i in "${used_by[@]}" ; do
  image_full="${image}:${image_tag}"
  # Detect if the image_tag already exists, if it does then we can assume the
  # image was created and a sha256 is available for it.
  if grep "CILIUM_RUNTIME_IMAGE=${image}:${image_tag}" "${i}" ; then
    sha256=$("${script_dir}/get-image-digest.sh" "${image_full}")
    if [ -n "${sha256}" ]; then
      image_full="${image_full}@${sha256}"
    fi
  fi
  sed "s|\(CILIUM_RUNTIME_IMAGE=\)${image}:.*\$|\1${image_full}|" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

do_check="${CHECK:-false}"
if [ "${do_check}" = "true" ] ; then
    git diff --exit-code "${used_by[@]}"
fi
