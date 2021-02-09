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
    ip -o link show master "${CNI_MASTER_DEVICE}" type veth | awk '{print $2}' | sed 's/@.*//g'
}

HOST_PREFIX=${HOST_PREFIX:-/host}
BIN_NAME=cilium-cni
CNI_DIR=${CNI_DIR:-${HOST_PREFIX}/opt/cni}
CNI_CONF_DIR=${CNI_CONF_DIR:-${HOST_PREFIX}/etc/cni/net.d}
CILIUM_CUSTOM_CNI_CONF=${CILIUM_CUSTOM_CNI_CONF:-false}

# Do not interact with the host's CNI directory when the user specified they
# are managing CNI configs externally.
if [ "${CILIUM_CUSTOM_CNI_CONF}" != "true" ]; then
    # .conf/.conflist/.json (undocumented) are read by kubelet/dockershim's CNI implementation.
    # Remove any active Cilium CNI configurations to prevent scheduling Pods during agent
    # downtime. Configs belonging to other CNI implementations have already been renamed
    # to *.cilium_bak during agent startup.
    echo "Removing active Cilium CNI configurations from ${CNI_CONF_DIR}..."
    find "${CNI_CONF_DIR}" -maxdepth 1 -type f \
    -name '*cilium*' -and \( \
        -name '*.conf' -or \
        -name '*.conflist' \
    \) -delete
fi

echo "Removing ${CNI_DIR}/bin/cilium-cni..."
rm -f "${CNI_DIR}/bin/${BIN_NAME}"
rm -f "${CNI_DIR}/bin/${BIN_NAME}.old"

if [[ "${CILIUM_FLANNEL_UNINSTALL_ON_EXIT}" == "true" ]]; then
    echo "Removing BPF programs from all containers and from ${CILIUM_FLANNEL_MASTER_DEVICE}"
    echo "Uninstalling cilium from ${CILIUM_FLANNEL_MASTER_DEVICE}"
    uninstall_cilium_from_flannel_master "${CILIUM_FLANNEL_MASTER_DEVICE}"

    for dev in $(get_list_of_veth_from_bridge "${CILIUM_FLANNEL_MASTER_DEVICE}"); do
        echo "Uninstalling cilium from ${dev}"
        uninstall_cilium_from_pod "${dev}"
    done
fi
