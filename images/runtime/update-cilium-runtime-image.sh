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

image="quay.io/cilium/cilium-runtime"

# shellcheck disable=SC2207
used_by=($(git grep -l CILIUM_RUNTIME_IMAGE= images/*/Dockerfile))

for i in "${used_by[@]}" ; do
  sed -E "s#((CILIUM_RUNTIME|BASE)_IMAGE=)${image}:.*\$#\1${image_full}#" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

# shellcheck disable=SC2207
jenkins_used_by=($(git grep -l "${image}:" jenkinsfiles/))

for i in "${jenkins_used_by[@]}" ; do
  sed -E "s#\"${image}:.*\"#\"${image_full}\"#" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

# shellcheck disable=SC2207
github_used_by=($(git grep -l "${image}:" .github/workflows/))

for i in "${github_used_by[@]}" ; do
  sed -E "s#${image}:.*#${image_full}#" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done

do_check="${CHECK:-false}"
if [ "${do_check}" = "true" ] ; then
    git diff --exit-code "${used_by[@]}"
fi
