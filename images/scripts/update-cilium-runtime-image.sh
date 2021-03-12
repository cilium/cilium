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

image_full="${image}:${image_tag}"
sha256=$("${script_dir}/get-image-digest.sh" "${image_full}" || echo "")
if [ -n "${sha256}" ]; then
  image_full="${image_full}@${sha256}"
fi

# shellcheck disable=SC2207
used_by=($(git grep -l CILIUM_RUNTIME_IMAGE= images/*/Dockerfile) $(git grep -l BASE_IMAGE= .github/workflows/) ".travis.yml")

for i in "${used_by[@]}" ; do
  sed -E "s#((CILIUM_RUNTIME|BASE)_IMAGE=)${image}:.*\$#\1${image_full}#" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

# shellcheck disable=SC2207
jenkins_used_by=($(git grep -l "${image}:" jenkinsfiles/))

for i in "${jenkins_used_by[@]}" ; do
  sed -E "s#\"${image}:.*\"#\"${image_full}\"#" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

do_check="${CHECK:-false}"
if [ "${do_check}" = "true" ] ; then
    git diff --exit-code "${used_by[@]}"
fi
