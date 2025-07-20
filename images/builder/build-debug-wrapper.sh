#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")

for arch in amd64 arm64 ; do
  mkdir -p "/out/linux/${arch}/bin"
  GOARCH="${arch}" CGO_ENABLED=0 go build -ldflags "-s -w" -o "/out/linux/${arch}/bin/debug-wrapper" "${SCRIPT_DIR}/debug-wrapper.go"
done
