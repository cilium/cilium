#!/bin/bash

# Copy the cilium-cni plugin binary to the host

set -e

HOST_PREFIX=${HOST_PREFIX:-/host}

BIN_NAME=cilium-cni
CNI_DIR=${CNI_DIR:-${HOST_PREFIX}/opt/cni}

if [ ! -d "${CNI_DIR}/bin" ]; then
	mkdir -p "${CNI_DIR}/bin"
fi

# Copy the binary and then rename so the move is atomic
install_cni() {
	src="$1"
	bin_name="$(basename $src)"
	tmp_dst="${CNI_DIR}/bin/.$bin_name.new"
	dst="${CNI_DIR}/bin/$bin_name"

	echo "Installing $bin_name to $dst ..."
	cp $src $tmp_dst && \
	mv $tmp_dst $dst && \
	echo "Wrote $dst"
}

# Install the CNI loopback driver if not installed already
if [ ! -f "${CNI_DIR}/bin/loopback" ]; then
	# Don't fail hard if this fails as it is usually not required
	install_cni /cni/loopback || true
fi

install_cni "/opt/cni/bin/${BIN_NAME}"
