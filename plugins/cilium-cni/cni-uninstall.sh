#!/bin/bash

set -e

function uninstall_cilium_from_flannel_master() {
    CNI_MASTER_DEVICE="${1}"
    # Those are the settings set by default from flannel
    [[ "$(tc filter show dev "${CNI_MASTER_DEVICE}" egress)" != "" ]] && \
        tc filter delete dev "${CNI_MASTER_DEVICE}" egress pref 1 handle 1 bpf || \
        echo 1 > "/proc/sys/net/ipv4/conf/${CNI_MASTER_DEVICE}/forwarding" && \
        echo 1 > "/proc/sys/net/ipv4/conf/${CNI_MASTER_DEVICE}/rp_filter" && \
        echo 0 > "/proc/sys/net/ipv4/conf/${CNI_MASTER_DEVICE}/accept_local" && \
        echo 1 > "/proc/sys/net/ipv4/conf/${CNI_MASTER_DEVICE}/send_redirects" && \
        echo 1 > "/proc/sys/net/ipv4/conf/all/rp_filter"
}

function uninstall_cilium_from_pod() {
    POD_VETH_SIDE_PAIR="${1}"
    [[ "$(tc filter show dev "${POD_VETH_SIDE_PAIR}" ingress)" != "" ]] && \
        tc filter delete dev "${POD_VETH_SIDE_PAIR}" ingress pref 1 handle 1 bpf || \
        echo 1 > "/proc/sys/net/ipv4/conf/${POD_VETH_SIDE_PAIR}/rp_filter"
}

function get_list_of_veth_from_bridge() {
    CNI_MASTER_DEVICE="${1}"
    echo "$(ip -o link show master "${CNI_MASTER_DEVICE}" type veth | awk '{print $2}' | sed 's/@.*//g')"
}

HOST_PREFIX=${HOST_PREFIX:-/host}
BIN_NAME=cilium-cni
CNI_DIR=${CNI_DIR:-${HOST_PREFIX}/opt/cni}

echo "Removing ${CNI_DIR}/bin/cilium-cni..."
rm -f ${CNI_DIR}/bin/${BIN_NAME}
rm -f ${CNI_DIR}/bin/${BIN_NAME}.old

if [[ "${CILIUM_FLANNEL_UNINSTALL_ON_EXIT}" == "true" ]]; then
    echo "Removing BPF programs from all containers and from ${CILIUM_FLANNEL_MASTER_DEVICE}"
    echo "Uninstalling cilium from ${CILIUM_FLANNEL_MASTER_DEVICE}"
    uninstall_cilium_from_flannel_master "${CILIUM_FLANNEL_MASTER_DEVICE}"

    for iDev in $(get_list_of_veth_from_bridge "${CILIUM_FLANNEL_MASTER_DEVICE}"); do
        echo "Uninstalling cilium from ${iDev}"
        uninstall_cilium_from_pod ${iDev}
    done
fi
