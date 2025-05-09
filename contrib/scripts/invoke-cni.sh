#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -eu
set -o pipefail

WORKLOAD="test1"
NETNS=${NETNS:-$WORKLOAD}
CNI_PATH=${CNI_PATH:-/opt/cni/bin/}
CNI=${CNI:-$CNI_PATH/cilium-cni}
IP_ADDR="192.0.2.3/24"
GW_ADDR="192.0.2.1"
MAC_ADDR="00:11:22:33:44:55"
IF_NUM="2"

NETWORK="$WORKLOAD-net"
HOSTIFNAME="$WORKLOAD-host"
TESTIFNAME="$WORKLOAD-net"

log() {
    >&2 echo ">> $@"
}

check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run this script with sudo."
        exit 1
    fi
}

setup() {
    log "Setting up..."
    ip link add dev "$HOSTIFNAME" \
                type veth \
                peer name "$TESTIFNAME"
    ip netns add "$NETNS"
    export CNI_COMMAND=ADD
    export CNI_CONTAINERID="$WORKLOAD"
    export CNI_NETNS="$NETWORK"
    export CNI_IFNAME="$TESTIFNAME"
    export CNI_PATH="$CNI_PATH"
    cat <<EOF | "${CNI}" || (>&2 echo && exit 1)
{
  "cniVersion": "1.0.0",
  "name": "cilium",
  "type": "cilium-cni",
  "prevResult": {
    "cniVersion": "1.0.0",
    "ips": [
        {
          "address": "$IP_ADDR",
          "gateway": "$GW_ADDR",
          "interface": $IF_NUM
        }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ],
    "interfaces": [
        {
            "name": "$NETNS-host",
            "mac": "$MAC_ADDR"
        }
    ]
  }
}
EOF
}

cleanup() {
    log "Cleaning up..."
    export CNI_COMMAND=DEL
    export CNI_CONTAINERID="$WORKLOAD"
    export CNI_NETNS="$NETWORK"
    export CNI_IFNAME="$TESTIFNAME"
    export CNI_PATH="$CNI_PATH"
    cat <<EOF | "${CNI}" ||:
{
  "cniVersion": "1.0.0",
  "name": "cilium",
  "type": "cilium-cni"
}
EOF
    ip netns del "$NETNS" ||:
    ip link del dev "$TESTIFNAME" ||:
}

main() {
    check_sudo

    trap cleanup EXIT
    setup
    read -r -p ">> Waiting for input before shutting down..."
}

main "$@"
