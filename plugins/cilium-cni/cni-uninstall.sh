#!/bin/bash

set -e

HOST_PREFIX=${HOST_PREFIX:-/host}
BIN_NAME=cilium-cni
CNI_DIR=${CNI_DIR:-${HOST_PREFIX}/opt/cni}
CNI_CONF_DIR=${CNI_CONF_DIR:-${HOST_PREFIX}/etc/cni/net.d}
CILIUM_CUSTOM_CNI_CONF=${CILIUM_CUSTOM_CNI_CONF:-false}

if [[ "$(cat /tmp/cilium/config-map/cni-uninstall 2>/dev/null || true)" != "true" ]]; then
    echo "cni-uninstall disabled, not removing CNI configuration"
    exit
fi

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
