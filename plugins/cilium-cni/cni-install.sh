#!/bin/sh

set -eu

HOST_PREFIX=${HOST_PREFIX:-/host}
CNI_CONF_NAME=${CNI_CONF_NAME:-10-cilium.conf}
MTU=${MTU:-1450}

CNI_DIR=${CNI_DIR:-${HOST_PREFIX}/opt/cni}
CILIUM_CNI_CONF=${CILIUM_CNI_CONF:-${HOST_PREFIX}/etc/cni/net.d/${CNI_CONF_NAME}}

mkdir -p ${CNI_DIR}/bin

# Install the CNI loopback driver if not installed already
if [ ! -f ${CNI_DIR}/bin/loopback ]; then
	echo "Installing loopback driver..."
	cp /cni/loopback ${CNI_DIR}/bin/
fi

echo "Installing cilium-cni to ${CNI_DIR}/bin/ ..."
cp /opt/cni/bin/cilium-cni ${CNI_DIR}/bin/

if [ -f "${CILIUM_CNI_CONF}" ]; then
	echo "Using existing ${CILIUM_CNI_CONF}..."
else
	echo "Installing new ${CILIUM_CNI_CONF}..."
	cat > ${CNI_CONF_NAME} <<EOF
{
    "name": "cilium",
    "type": "cilium-cni",
    "mtu": ${MTU}
}
EOF
	mkdir -p $(dirname $CILIUM_CNI_CONF)

	mv ${CNI_CONF_NAME} ${CILIUM_CNI_CONF}
fi
