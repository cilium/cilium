#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

MAKER_IMAGE="${MAKER_IMAGE:-docker.io/cilium/image-maker:bc81755ec8f6c5afcb10a416cef73f99a35fee2c}"

root_dir="$(git rev-parse --show-toplevel)"

if [ -z "${MAKER_CONTAINER+x}" ] ; then
   exec docker run --rm --volume "${root_dir}:/src" --workdir /src/images "${MAKER_IMAGE}" "/src/images/scripts/$(basename "${0}")"
fi

find . -name '*.sh' -exec shellcheck {} +
