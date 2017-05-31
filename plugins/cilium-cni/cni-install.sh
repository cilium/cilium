#!/bin/sh

set -eu

HOST_PREFIX=${HOST_PREFIX:-/host}
CNI_CONF_NAME=${CNI_CONF_NAME:-10-cilium.conf}
MTU=${MTU:-1450}

CILIUM_CNI=${CILIUM_CNI:-${HOST_PREFIX}/opt/cni/bin/cilium-cni}
CILIUM_CNI_CONF=${CILIUM_CNI_CONF:-${HOST_PREFIX}/etc/cni/net.d/${CNI_CONF_NAME}}

# Install cilium-cni binary tohost
echo "Installing $CILIUM_CNI ..."
cp /opt/cni/bin/cilium-cni ${CILIUM_CNI}

if [ -f "${CILIUM_CNI_CONF}" ]; then
	echo "Using existing ${CILIUM_CNI_CONF}..."
else
	echo "Installing new $CILIUM_CNI_CONF ..."
	cat > ${CNI_CONF_NAME} <<EOF
{
    "name": "cilium",
    "type": "cilium-cni",
    "mtu": ${MTU}
}
EOF

	mv ${CNI_CONF_NAME} ${CILIUM_CNI_CONF}
fi
