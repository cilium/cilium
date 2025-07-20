#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

if [ "$#" -ne 1 ] ; then
  echo "$0 supports exactly 1 argument"
  exit 1
fi

function getSHA() {
  if command -v sha256sum &> /dev/null; then
    sha256sum | cut -d " " -f 1
  elif command -v openssl &> /dev/null; then
    openssl sha256 | cut -d " " -f 2
  else
    echo "$0 requires sha256sum or openssl to be installed."
    exit 1
  fi
}

inspect=$(docker buildx imagetools inspect "${1}" --raw 2>/dev/null | awk 'NR>1 { print p } { p = $0 } END { printf("%s", $0) }' | getSHA )
# shellcheck disable=SC2181
if [ $? -eq 0 ]; then
  echo "sha256:${inspect}"
else
  echo ""
fi
