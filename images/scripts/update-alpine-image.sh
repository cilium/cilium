#!/bin/bash

# Copyright 2017-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

if [ "$#" -gt 1 ] ; then
  echo "$0 supports at most 1 argument"
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

alpine_version=3.13.1

image="${1:-docker.io/library/alpine:${alpine_version}}"

image_digest="$("${script_dir}/get-image-digest.sh" "${image}")"

if [ -z "${image_digest}" ]; then
  echo "Image digest not available"
  exit 1
fi

# shellcheck disable=SC2207
used_by=($(git grep -l ALPINE_IMAGE= images/*/Dockerfile))

for i in "${used_by[@]}" ; do
    # alpine images with image digest
    sed "s|ALPINE_IMAGE=docker\.io/library/alpine:[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*@.*|ALPINE_IMAGE=${image}@${image_digest}|" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done
