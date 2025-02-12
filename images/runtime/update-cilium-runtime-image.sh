#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

image_full=${1}
image="${image_full%%:*}"
root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

# shellcheck disable=SC2207
used_by=($(git grep -l "${image}:" .github/actions/; find . -type f -name Dockerfile -print0 | xargs -0 git grep -l CILIUM_RUNTIME_IMAGE= | sort -u))

for i in "${used_by[@]}" ; do
  sed -E "s#${image}:.*#${image_full}#" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

do_check="${CHECK:-false}"
if [ "${do_check}" = "true" ] ; then
  git diff --exit-code "${used_by[@]}" || (echo "Runtime images out of date, " \
    "see https://docs.cilium.io/en/latest/contributing/development/images/#update-cilium-builder-runtime-images." && \
    exit 1)
fi
