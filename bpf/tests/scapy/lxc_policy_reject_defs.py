# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

v4_lxc_to_external = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_pod_one, dst=v4_ext_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one,flags="S")
)

v4_lxc_to_external_icmp_unreach = (
    Ether(src=mac_two, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one, id=0) /
    ICMP(type="dest-unreach", code="communication-prohibited") /
    IPerror(bytes(v4_lxc_to_external[IP])[:28])
)

v6_lxc_to_external = (
    Ether(src=mac_one, dst=mac_two) /
    IPv6(src=v6_pod_one, dst=v6_ext_node_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one,flags="S")
)

v6_lxc_to_external_icmp_unreach = (
    Ether(src=mac_two, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    ICMPv6DestUnreach(code=1) /
    IPerror6(bytes(v6_lxc_to_external[IPv6]))
)
