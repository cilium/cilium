#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

MAKEFILEPATH=${MAKEFILEPATH:-"./install/kubernetes/Makefile.values"}
image="$(sed -n -E 's/^export[[:space:]]+CILIUM_ENVOY_REPO[?]?=(.*)$/\1/p' "${MAKEFILEPATH}")"
image_tag="$(sed -n -E 's/^export[[:space:]]+CILIUM_ENVOY_VERSION[?]?=(.*)$/\1/p' "${MAKEFILEPATH}")"
image_sha256="$(sed -n -E 's/^export[[:space:]]+CILIUM_ENVOY_DIGEST[?]?=(.*)$/\1/p' "${MAKEFILEPATH}")"

if [[ ! "${image_tag}" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    echo "Invalid image_tag format: ${image_tag}"
    exit 1
fi

if [[ ! "${image_sha256}" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "Invalid image_sha256 format: ${image_sha256}"
    exit 1
fi

if [[ ! "${image}" =~ ^[a-zA-Z0-9./:-]+$ ]]; then
    echo "Invalid image format: ${image}"
    exit 1
fi

# pre-check for sed, in case that this script may fail to detect change when the `sed` command fails to replace the string and return code 0
image_escaped="${image//./\\.}"
image_regular="(ARG CILIUM_ENVOY_IMAGE=${image_escaped}:)(.*)(@sha256:[0-9a-z]*)"
grep -E "${image_regular}" ./images/cilium/Dockerfile &>/dev/null || exit 1
sed -i -E "s|${image_regular}|\1${image_tag}@${image_sha256}|" ./images/cilium/Dockerfile

echo "Checking for different Cilium Envoy images"
git diff --exit-code ./images/cilium/Dockerfile
