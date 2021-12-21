#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
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

go_version=1.16.5
# Do not upgrade to alpine 3.13 as its nslookup tool returns 1, instead of 0
# for domain name lookups.
go_version_alpine=${go_version}-alpine3.12

image="${1:-docker.io/library/golang:${go_version}}"
image_digest="$("${script_dir}/get-image-digest.sh" "${image}")"

if [ -z "${image_digest}" ]; then
  echo "Image digest not available"
  exit 1
fi

image_alpine="${1:-docker.io/library/golang:${go_version_alpine}}"
image_alpine_digest="$("${script_dir}/get-image-digest.sh" "${image}")"

if [ -z "${image_alpine_digest}" ]; then
  echo "Image alpine digest not available"
  exit 1
fi

# shellcheck disable=SC2207
used_by=($(git grep -l GOLANG_IMAGE= images/*/Dockerfile))

for i in "${used_by[@]}" ; do
    # golang images with image digest
    sed "s|GOLANG_IMAGE=docker\.io/library/golang:[0-9][0-9]*\.[0-9][0-9]*\(\.[0-9][0-9]*\)\?@.*|GOLANG_IMAGE=${image}@${image_digest}|" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
    # other golang images (e.g. golang-alpine images)
    sed "s|GOLANG_IMAGE=docker\.io/library/golang:[0-9][0-9]*\.[0-9][0-9]*\(\.[0-9][0-9]*\)\?-\(.*\)@.*|GOLANG_IMAGE=${image_alpine}@${image_alpine_digest}|" "${i}" > "${i}.sedtmp" && mv "${i}.sedtmp" "${i}"
done
