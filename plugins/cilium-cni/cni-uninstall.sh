#!/bin/sh

set -eu

HOST_PREFIX=${HOST_PREFIX:-/host}
CNI_CONF_NAME=${CNI_CONF_NAME:-10-cilium.conf}

CILIUM_CNI=${CILIUM_CNI:-${HOST_PREFIX}/opt/cni/bin/cilium-cni}
CILIUM_CNI_CONF=${CILIUM_CNI_CONF:-${HOST_PREFIX}/etc/cni/net.d/${CNI_CONF_NAME}}

echo "Removing ${CILIUM_CNI} ..."
rm -f ${CILIUM_CNI}

echo "Removing ${CILIUM_CNI_CONF} ..."
rm -f ${CILIUM_CNI_CONF}
