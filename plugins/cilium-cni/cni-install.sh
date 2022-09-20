#!/bin/bash

# This script copies over the cilium-cni and localhost CNI plugin binaries
# to the host.

set -e

BIN_NAME=cilium-cni
CNI_BIN_DIR=/host/opt/cni/bin

function atomic_cp {
  local src="$1"
  local dst="$2"

  cp "${src}" "${dst}.tmp"
  mv "${dst}.tmp" "${dst}"
}

# Install the CNI loopback driver if not installed already
if [ ! -f "${CNI_BIN_DIR}/loopback" ]; then
	echo "Installing loopback driver..."

	# Don't fail hard if this fails as it is usually not required
	cp /cni/loopback "${CNI_BIN_DIR}/loopback" || true
fi

echo "Installing ${BIN_NAME} to ${CNI_BIN_DIR} ..."


atomic_cp "/opt/cni/bin/${BIN_NAME}" "${CNI_BIN_DIR}/${BIN_NAME}"
