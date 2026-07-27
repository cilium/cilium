# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

## Wireguard from overlay (tc_wireguard_from_overlay.c)

# TCP packet from pod to pod through overlay network (input packet)
v4_overlay_tcp_packet = (
    Ether(dst=mac_two, src=mac_one) /
    IP(src=v4_pod_one, dst=v4_pod_two) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one)
)

# Expected packet after MAC rewriting for local delivery
# MACs are rewritten: src=mac_four (DEST_NODE_MAC), dst=mac_three (DEST_EP_MAC)
# TTL is decremented by 1 during forwarding (64 -> 63)
# IP checksum is recalculated to reflect TTL change
v4_overlay_tcp_packet_rewritten = (
    Ether(dst=mac_three, src=mac_four) /
    IP(src=v4_pod_one, dst=v4_pod_two, ttl=63) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one)
)
