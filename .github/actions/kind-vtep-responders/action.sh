#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
#
# Start VXLAN tunnel endpoint responder containers for VTEP integration testing.
# Each responder is an Alpine container with a kernel VXLAN interface that
# automatically responds to ICMP echo requests on the configured inner IP.

set -euo pipefail

NETWORK="$1"
VTEP_A_IP="$2"
VTEP_B_IP="$3"
INNER_IP="$4"

# Cilium VTEP VXLAN parameters (confirmed from BPF source):
#   VNI=2: WORLD_IPV4_ID -> WORLD_ID=2 via get_tunnel_id() (bpf/lib/common.h)
#   Port=8472: Cilium default VXLAN port (pkg/defaults/defaults.go)
VXLAN_PORT=8472
VNI=2

# Discover Kind node IPs and MACs for FDB entries (so VXLAN replies reach the right node).
# Use unicast FDB entries (real MACs) instead of the catch-all 00:00:00:00:00:00 to avoid
# unnecessary broadcast flooding on the Kind Docker network.
# Use network-specific query to avoid concatenating IPs from multiple networks.
node_ip()  { docker inspect "$1" -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}"; }
node_mac() { docker inspect "$1" -f "{{(index .NetworkSettings.Networks \"$NETWORK\").MacAddress}}"; }

WORKER1_IP=$(node_ip  kind-worker)  ; WORKER1_MAC=$(node_mac kind-worker)
WORKER2_IP=$(node_ip  kind-worker2) ; WORKER2_MAC=$(node_mac kind-worker2)
CP_IP=$(node_ip kind-control-plane) ; CP_MAC=$(node_mac kind-control-plane)

echo "Kind node IPs/MACs:"
echo "  control-plane: $CP_MAC $CP_IP"
echo "  worker:        $WORKER1_MAC $WORKER1_IP"
echo "  worker2:       $WORKER2_MAC $WORKER2_IP"

# Collect optional extra workers (kind-worker3, kind-worker4, …) dynamically.
EXTRA_FDB=""
for i in 3 4 5 6; do
  name="kind-worker${i}"
  if docker inspect "$name" &>/dev/null; then
    extra_ip=$(node_ip  "$name")
    extra_mac=$(node_mac "$name")
    echo "  worker${i}:       $extra_mac $extra_ip"
    EXTRA_FDB="$EXTRA_FDB bridge fdb append $extra_mac dev vxlan0 dst $extra_ip;"
  fi
done

setup_responder() {
  local NAME="$1"
  local OUTER_IP="$2"
  local OUTPUT_KEY="$3"
  local ZONE_NODE_IP="$4"  # the Kind node this responder serves (for ARP flood)

  echo "Setting up $NAME (outer=$OUTER_IP, inner=$INNER_IP)..."

  docker run -d --name "$NAME" \
    --network "$NETWORK" \
    --ip "$OUTER_IP" \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    alpine sleep infinity

  # Install iproute2 (not included in base Alpine) and create VXLAN tunnel interface.
  # The kernel handles VXLAN encap/decap natively and responds to ICMP automatically.
  # nolearning: disable MAC learning, use explicit unicast FDB entries instead.
  docker exec "$NAME" sh -c "apk add --no-cache iproute2 tcpdump"

  docker exec "$NAME" sh -c "
    ip link add vxlan0 type vxlan id $VNI dstport $VXLAN_PORT local $OUTER_IP
    ip addr add ${INNER_IP}/24 dev vxlan0
    ip link set vxlan0 mtu 1450
    ip link set vxlan0 up

    # Unicast FDB entries: map each Kind node's MAC to its IP so VXLAN replies
    # for known MACs are sent directly without broadcasting.
    bridge fdb append $CP_MAC      dev vxlan0 dst $CP_IP
    bridge fdb append $WORKER1_MAC dev vxlan0 dst $WORKER1_IP
    bridge fdb append $WORKER2_MAC dev vxlan0 dst $WORKER2_IP
    $EXTRA_FDB

    # Flood entry for the zone-specific node only, so ARP requests for pod IPs
    # reach the right node without broadcasting to the entire Kind network.
    bridge fdb append 00:00:00:00:00:00 dev vxlan0 dst $ZONE_NODE_IP

    # Route the pod CIDR through vxlan0 so ICMP replies have a path back.
    ip route add 10.244.0.0/16 dev vxlan0
  "

  # Capture the auto-generated MAC of the VXLAN interface.
  # This MAC is used in the CiliumVTEPConfig CRD's "mac" field.
  local MAC
  MAC=$(docker exec "$NAME" cat /sys/class/net/vxlan0/address)
  echo "  $NAME vxlan0 MAC: $MAC"
  echo "${OUTPUT_KEY}=${MAC}" >> "$GITHUB_OUTPUT"
}

setup_responder "vtep-responder-a" "$VTEP_A_IP" "vtep_a_mac" "$WORKER1_IP"
setup_responder "vtep-responder-b" "$VTEP_B_IP" "vtep_b_mac" "$WORKER2_IP"

echo ""
echo "VTEP responders started on network $NETWORK"
echo "  vtep-responder-a: outer=$VTEP_A_IP inner=$INNER_IP"
echo "  vtep-responder-b: outer=$VTEP_B_IP inner=$INNER_IP"
