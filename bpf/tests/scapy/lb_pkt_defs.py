# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

lb4_clusterip = (
    Ether(dst=mac_two, src=mac_one) /
    IP(src=v4_ext_one, dst=v4_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_svc_one) /
    Raw("S"*1)
)

lb4_clusterip_post_dnat = (
    Ether(dst=mac_two, src=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one) /
    Raw("S"*1)
)

lb6_clusterip = (
    Ether(dst=mac_two, src=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_svc_one) /
    Raw("S"*1)
)

lb6_clusterip_post_dnat = (
    Ether(dst=mac_two, src=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one) /
    Raw("S"*1)
)

# Create two TCP fragments over IPv4:
# 1. Ether(14) + IP(20) + TCP(20) + Raw(1) = 55B
# 2. Ether(14) + IP(20) + Raw(1)           = 35B.
#
# Dev Notes:
# - `frag` is in 8-byte units.
# - `id` is in big endian.
lb4_nodeport_fragment1 = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_svc_one, flags='MF', frag=0, id=256, proto=6) /
    TCP(sport=tcp_src_one, dport=tcp_svc_one) /
    Raw(load="S" * 1)
)

lb4_nodeport_fragment1_post_dnat = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one, flags='MF', frag=0, id=256, proto=6) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one) /
    Raw(load="S" * 1)
)

lb4_nodeport_fragment2 = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_svc_one, flags='', frag=(20+60)//8, id=256, proto=6) /
    Raw(load="S" * 1)
)

lb4_nodeport_fragment2_post_dnat = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one, flags='', frag=(20+60)//8, id=256, proto=6) /
    Raw(load="S" * 1)
)
