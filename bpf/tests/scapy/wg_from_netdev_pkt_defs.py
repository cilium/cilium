# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from pkt_defs_common import (
    mac_one,
    mac_two,
    v4_node_one,
    v4_node_two,
    v6_node_one,
    v6_node_two,
)

## Wireguard from netdev (wireguard_from_netdev.c)

wireguard_port = 51871

v4_wireguard = (
    Ether(dst=mac_two, src=mac_one)
    / IP(src=v4_node_one, dst=v4_node_two)
    / UDP(sport=wireguard_port, dport=wireguard_port)
)

v4_wireguard_sport_mismatch = (
    Ether(dst=mac_two, src=mac_one)
    / IP(src=v4_node_one, dst=v4_node_two)
    / UDP(sport=wireguard_port + 1, dport=wireguard_port)
)

v4_wireguard_proto_mismatch = (
    Ether(dst=mac_two, src=mac_one)
    / IP(src=v4_node_one, dst=v4_node_two)
    / TCP(sport=wireguard_port, dport=wireguard_port)
)

v6_wireguard = (
    Ether(dst=mac_two, src=mac_one)
    / IPv6(src=v6_node_one, dst=v6_node_two)
    / UDP(sport=wireguard_port, dport=wireguard_port)
)

v6_wireguard_sport_mismatch = (
    Ether(dst=mac_two, src=mac_one)
    / IPv6(src=v6_node_one, dst=v6_node_two)
    / UDP(sport=wireguard_port + 1, dport=wireguard_port)
)

v6_wireguard_proto_mismatch = (
    Ether(dst=mac_two, src=mac_one)
    / IPv6(src=v6_node_one, dst=v6_node_two)
    / TCP(sport=wireguard_port, dport=wireguard_port)
)
