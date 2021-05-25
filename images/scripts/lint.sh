#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

MAKER_IMAGE="${MAKER_IMAGE:-quay.io/cilium/image-maker:ca3f9135c0c8cb88c979f829d93a167838776615@sha256:b64f9168f52dae5538cd8ca06922e522eb84e36d3f727583c352266e3ed15894}"

root_dir="$(git rev-parse --show-toplevel)"

if [ -z "${MAKER_CONTAINER+x}" ] ; then
   exec docker run --rm --volume "${root_dir}:/src" --workdir /src/images "${MAKER_IMAGE}" "/src/images/scripts/$(basename "${0}")"
fi

# shellcheck disable=SC2207
scripts=($(find . -name '*.sh' -executable))

for script in "${scripts[@]}" ; do
  shellcheck --external-source --source-path="$(dirname "${script}")" "${script}"
done
