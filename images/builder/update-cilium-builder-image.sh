#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

image_full=${1}
root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

image="quay.io/cilium/cilium-builder"

# shellcheck disable=SC2207
used_by=($(find . -type f -name Dockerfile -print0 | xargs -0 git grep -l CILIUM_BUILDER_IMAGE=))

for i in "${used_by[@]}" ; do
  sed -E "s#(CILIUM_BUILDER_IMAGE=|image: )${image}:.*\$#\1${image_full}#" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

used_by=(".devcontainer/devcontainer.json")

for i in "${used_by[@]}" ; do
  sed -E "s#(\"image\": \")${image}:.*\",\$#\1${image_full}\",#" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

do_check="${CHECK:-false}"
if [ "${do_check}" = "true" ] ; then
  git diff --exit-code "${used_by[@]}" || (echo "Builder images out of date, " \
    "see https://docs.cilium.io/en/latest/contributing/development/images/#update-cilium-builder-runtime-images." && \
    exit 1)
fi
