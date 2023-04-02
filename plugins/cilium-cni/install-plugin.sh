#!/bin/bash

# Copy the cilium-cni plugin binary to the host

set -e

HOST_PREFIX=${HOST_PREFIX:-/host}

BIN_NAME=cilium-cni
CNI_DIR=${CNI_DIR:-${HOST_PREFIX}/opt/cni}
CILIUM_CNI_CONF=${CILIUM_CNI_CONF:-${HOST_PREFIX}/etc/cni/net.d/${CNI_CONF_NAME}}

if [ ! -d "${CNI_DIR}/bin" ]; then
	mkdir -p "${CNI_DIR}/bin"
fi

# Install the CNI loopback driver if not installed already
if [ ! -f "${CNI_DIR}/bin/loopback" ]; then
	echo "Installing loopback driver..."

	# Don't fail hard if this fails as it is usually not required
	cp /cni/loopback "${CNI_DIR}/bin/" || true
fi

echo "Installing ${BIN_NAME} to ${CNI_DIR}/bin/ ..."

# Copy the binary, then do a rename
# so the move is atomic
rm -f "${CNI_DIR}/bin/${BIN_NAME}.new" || true
cp "/opt/cni/bin/${BIN_NAME}" "${CNI_DIR}/bin/.${BIN_NAME}.new"
mv "${CNI_DIR}/bin/.${BIN_NAME}.new" "${CNI_DIR}/bin/${BIN_NAME}"

echo "wrote ${CNI_DIR}/bin/${BIN_NAME}"