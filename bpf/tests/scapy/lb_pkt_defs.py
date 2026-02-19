# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from pkt_defs_common import (
    mac_one,
    mac_two,
    v4_ext_one,
    v4_svc_one,
    v6_ext_node_one,
    v6_svc_one,
    tcp_src_one,
    tcp_svc_one,
)

lb4_clusterip = (
    Ether(src=mac_one, dst=mac_two)
    / IP(src=v4_ext_one, dst=v4_svc_one)
    / TCP(sport=tcp_src_one, dport=tcp_svc_one)
    / Raw("S" * 1)
)

lb6_clusterip = (
    Ether(src=mac_one, dst=mac_two)
    / IPv6(src=v6_ext_node_one, dst=v6_svc_one)
    / TCP(sport=tcp_src_one, dport=tcp_svc_one)
    / Raw("S" * 1)
)
