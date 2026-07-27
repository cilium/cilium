#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

MAKER_IMAGE="${MAKER_IMAGE:-quay.io/cilium/image-maker:7de7f1c855ce063bdbe57fdfb28599a3ad5ec8f1@sha256:dde8500cbfbb6c41433d376fdfcb3831e2df9cec50cf4f49e8553dc6eba74e72}"

root_dir="$(git rev-parse --show-toplevel)"

if [ -z "${MAKER_CONTAINER+x}" ] ; then
   exec docker run --rm --volume "${root_dir}:/src" --workdir /src/images "${MAKER_IMAGE}" "/src/images/scripts/$(basename "${0}")"
fi

# shellcheck disable=SC2207
scripts=($(find . -name '*.sh' -executable))

for script in "${scripts[@]}" ; do
  shellcheck --external-source --source-path="$(dirname "${script}")" "${script}"
done
