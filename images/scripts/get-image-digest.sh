#!/bin/bash

# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

if [ "$#" -ne 1 ] ; then
  echo "$0 supports exactly 1 argument"
  exit 1
fi

if [ "$(uname)" != "Linux" ]; then
  function sha256sum() { openssl sha256; }
fi

inspect=$(docker buildx imagetools inspect "${1}" --raw 2>/dev/null | awk 'NR>1 { print p } { p = $0 } END { printf("%s", $0) }' | sha256sum | cut -d " " -f 1 )
# shellcheck disable=SC2181
if [ $? -eq 0 ]; then
  echo "sha256:${inspect}"
else
  echo ""
fi
