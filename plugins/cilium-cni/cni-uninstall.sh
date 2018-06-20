#!/bin/sh

set -eu

HOST_PREFIX=${HOST_PREFIX:-/host}
CNI_CONF_NAME=${CNI_CONF_NAME:-00-cilium.conf}

BIN_NAME=cilium-cni
CNI_DIR=${CNI_DIR:-${HOST_PREFIX}/opt/cni}
CILIUM_CNI_CONF=${CILIUM_CNI_CONF:-${HOST_PREFIX}/etc/cni/net.d/${CNI_CONF_NAME}}

echo "Removing ${CNI_DIR}/bin/cilium-cni..."
rm -f ${CNI_DIR}/bin/${BIN_NAME}
rm -f ${CNI_DIR}/bin/${BIN_NAME}.old

echo "Removing ${CILIUM_CNI_CONF} ..."
rm -f ${CILIUM_CNI_CONF}
