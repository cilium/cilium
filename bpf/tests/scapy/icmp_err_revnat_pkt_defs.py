# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

# outer IPv4 (pod_two -> pod_one), ICMP Destination Unreachable / Fragmentation Needed,
# embedded original IPv4 + TCP with SNAT'd port
icmp4_err_frag_needed_for_revnat = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_pod_two, dst=v4_pod_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IP(src=v4_pod_one, dst=v4_pod_two, flags="DF") /
    TCP(sport=32768, dport=80)  # NODEPORT_PORT_MIN_NAT (SNAT'd port)
)

# After rev-NAT: pod_two -> node_one, with original port restored
icmp4_err_frag_needed_after_revnat = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_pod_two, dst=v4_node_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IP(src=v4_node_one, dst=v4_pod_two, flags="DF") /
    TCP(sport=3030, dport=80)  # original port restored
)

# Full inner TCP header + complete data payload
icmp4_err_nodeport_revnat_full_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_node_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IP(src=v4_node_one, dst=v4_ext_one, flags="DF") /
    TCP(sport=32768, dport=tcp_src_one, seq=tcp_default_seq) /
    Raw(default_data)
)

# After revSNAT: outer daddr -> pod_ip, inner saddr -> pod_ip, sport restored
icmp4_err_nodeport_revnat_full_tcp_after = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IP(src=v4_pod_one, dst=v4_ext_one, flags="DF") /
    TCP(sport=tcp_src_one, dport=tcp_src_one, seq=tcp_default_seq) /
    Raw(default_data)
)

# Inner TCP truncated to first 8 bytes: sport + dport + seq (RFC 792 minimum)
_nodeport_tcp_hdr_min = bytes(TCP(sport=32768, dport=tcp_src_one, seq=tcp_default_seq))[:8]
icmp4_err_nodeport_revnat_min_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_node_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IP(src=v4_node_one, dst=v4_ext_one, flags="DF", proto=6) /
    Raw(_nodeport_tcp_hdr_min)
)

# After revSNAT (min TCP): outer daddr -> pod_ip, inner saddr -> pod_ip, sport restored
_nodeport_tcp_hdr_min_after = bytes(TCP(sport=tcp_src_one, dport=tcp_src_one, seq=tcp_default_seq))[:8]
icmp4_err_nodeport_revnat_min_tcp_after = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IP(src=v4_pod_one, dst=v4_ext_one, flags="DF", proto=6) /
    Raw(_nodeport_tcp_hdr_min_after)
)

def _icmp6_nodeport_revnat_pkt(inner_l4):
    """Outer ICMPv6 PKT_TOO_BIG wrapper (pre-revSNAT): ext -> node, inner node -> ext."""
    return (
        Ether(src=mac_one, dst=mac_two) /
        IPv6(src=v6_ext_node_one, dst=v6_node_one) /
        ICMPv6PacketTooBig(mtu=1500) /
        IPv6(src=v6_node_one, dst=v6_ext_node_one) /
        inner_l4
    )

def _icmp6_nodeport_revnat_after_pkt(inner_l4):
    """Outer ICMPv6 PKT_TOO_BIG wrapper (post-revSNAT): ext -> pod, inner pod -> ext."""
    return (
        Ether(src=mac_one, dst=mac_two) /
        IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
        ICMPv6PacketTooBig(mtu=1500) /
        IPv6(src=v6_pod_one, dst=v6_ext_node_one) /
        inner_l4
    )

icmp6_err_nodeport_revnat_full_tcp = _icmp6_nodeport_revnat_pkt(
    TCP(sport=30001, dport=1234, seq=tcp_default_seq) / Raw(default_data)
)

icmp6_err_nodeport_revnat_full_tcp_after = _icmp6_nodeport_revnat_after_pkt(
    TCP(sport=20, dport=1234, seq=tcp_default_seq) / Raw(default_data)
)

icmp6_err_nodeport_revnat_full_udp = _icmp6_nodeport_revnat_pkt(
    TCP(sport=30001, dport=1234) / Raw(default_data)
)

icmp6_err_nodeport_revnat_full_udp_after = _icmp6_nodeport_revnat_after_pkt(
    TCP(sport=20, dport=1234) / Raw(default_data)
)

