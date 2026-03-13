# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

unsupported_drop_v4_gre_v4_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_svc_one) /
    GRE() /
    IP(src=v4_ext_two, dst=v4_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one) /
    Raw(default_data)
)

unsupported_drop_v6_gre_v6_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    IPv6(src=v6_ext_node_one, dst=v6_svc_one) /
    GRE() /
    IPv6(src=v6_ext_node_two, dst=v6_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one) /
    Raw(default_data)
)

unsupported_drop_v4_esp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_svc_one) /
    ESP(spi=123456789, seq=12345, data=default_data)
)

unsupported_drop_v6_esp = (
    Ether(src=mac_one, dst=mac_two) /
    IPv6(src=v6_ext_node_one, dst=v6_svc_one) /
    ESP(spi=123456789, seq=12345, data=default_data)
)

