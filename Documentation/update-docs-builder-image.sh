#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

image_full=${1}
image="${image_full%%:*}"
root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

# shellcheck disable=SC2207
used_by=($(git grep -l "${image}:" .github/workflows/))

for i in "${used_by[@]}" ; do
  sed -E "s#${image}:.*#${image_full}#" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

do_check="${CHECK:-false}"
if [ "${do_check}" = "true" ] ; then
    git diff --exit-code "${used_by[@]}" || (echo "docs-builder image out of date" && \
    exit 1)
fi
