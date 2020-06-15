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

image="docker.io/cilium/cilium-runtime-dev"

image_tag="$(WITHOUT_SUFFIX=1 "${script_dir}/make-image-tag.sh" images/runtime)"

# shellcheck disable=SC2207
used_by=($(git grep -l CILIUM_RUNTIME_IMAGE= images/*/Dockerfile))

for i in "${used_by[@]}" ; do
  sed "s|\(CILIUM_RUNTIME_IMAGE=\)${image}:.*\$|\1${image}:${image_tag}|" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done
