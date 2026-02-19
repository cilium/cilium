# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

lb4_clusterip = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_svc_one) /
    Raw("S"*1)
)

lb4_clusterip_post_dnat = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one) /
    Raw("S"*1)
)

lb6_clusterip = (
    Ether(src=mac_one, dst=mac_two) /
    IPv6(src=v6_ext_node_one, dst=v6_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_svc_one) /
    Raw("S"*1)
)

lb6_clusterip_post_dnat = (
    Ether(src=mac_one, dst=mac_two) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one) /
    Raw("S"*1)
)
