#!/bin/sh

set -eu

HOST_PREFIX=${HOST_PREFIX:-/host}
CNI_CONF_NAME=${CNI_CONF_NAME:-10-cilium.conf}

CNI_DIR=${CNI_DIR:-${HOST_PREFIX}/opt/cni}
CILIUM_CNI_CONF=${CILIUM_CNI_CONF:-${HOST_PREFIX}/etc/cni/net.d/${CNI_CONF_NAME}}

echo "Removing ${CNI_DIR}/bin/cilium-cni..."
rm -f ${CNI_DIR}/bin/cilium-cni

echo "Removing ${CILIUM_CNI_CONF} ..."
rm -f ${CILIUM_CNI_CONF}
