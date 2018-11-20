#!/bin/sh

set -eu

HOST_PREFIX=${HOST_PREFIX:-/host}
if [ -z "${CILIUM_POLICY_ENFORCEMENT_INTERFACE}" ]; then
    CNI_CONF_NAME=${CNI_CONF_NAME:-05-cilium.conf}
else
    CNI_CONF_NAME=${CNI_CONF_NAME:-04-cilium.conflist}
fi

BIN_NAME=cilium-cni
CNI_DIR=${CNI_DIR:-${HOST_PREFIX}/opt/cni}
CILIUM_CNI_CONF=${CILIUM_CNI_CONF:-${HOST_PREFIX}/etc/cni/net.d/${CNI_CONF_NAME}}

echo "Removing ${CNI_DIR}/bin/cilium-cni..."
rm -f ${CNI_DIR}/bin/${BIN_NAME}
rm -f ${CNI_DIR}/bin/${BIN_NAME}.old

echo "Removing ${CILIUM_CNI_CONF} ..."
rm -f ${CILIUM_CNI_CONF}

if [ -z "${CILIUM_POLICY_ENFORCEMENT_CLEAN_UP}" ]; then
    echo "Removing BPF programs from all containers and from ${CILIUM_POLICY_ENFORCEMENT_INTERFACE}"
    tc filter delete dev cni0 egress pref 1 handle 1 bpf
    # TODO create script to detect all interfaces that have bpf programs
    # installed
fi
