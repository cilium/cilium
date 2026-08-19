# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

# Shared header layers for the egress TCP flow, pre- and post-masquerade.
_ip_hdr_egress = IP(src=v4_pod_one, dst=v4_ext_one, flags="DF")
_tcp_hdr_egress = TCP(sport=tcp_src_two, dport=tcp_dst_one, seq=tcp_default_seq)

# Pod -> external host as goes into to-netdev host device (pre-masquerading).
# pod_ip:33440 -> ext_ip:22331
# The intention is that this should setup the correct nat entries for
# testing revSNAT.
# We use tcp_src_two=33440 which is above the nodeport minimum default value
# meaning that, assuming a empty nat map, the SNAT mapping can reuse the same
# port.
icmp4_err_revnat_egress_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    _ip_hdr_egress /
    _tcp_hdr_egress /
    Raw(default_data)
)

# Post-masquerade: saddr rewritten to node IP. Ports are unchanged because
# tcp_src_two (33440) > NODEPORT_PORT_MIN_NAT so the same source port is reused.
_ip_hdr_egress_post = IP(src=v4_node_one, dst=v4_ext_one, flags="DF")
_tcp_hdr_egress_post = TCP(sport=tcp_src_two, dport=tcp_dst_one, seq=tcp_default_seq)
icmp4_err_revnat_egress_post_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    _ip_hdr_egress_post /
    _tcp_hdr_egress_post /
    Raw(default_data)
)

# Full inner TCP header + complete data payload
icmp4_err_revnat_full_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_node_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IPerror(**_ip_hdr_egress_post.fields) /
    TCPerror(**_tcp_hdr_egress_post.fields) /
    Raw(default_data)
)

# After revSNAT: outer daddr -> pod_ip, inner saddr -> pod_ip. The ports are
# unchanged because the SNAT preserved the source port (see above).
icmp4_err_revnat_full_tcp_after = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IPerror(**_ip_hdr_egress.fields) /
    TCPerror(**_tcp_hdr_egress.fields) /
    Raw(default_data)
)

# Inner TCP truncated to first 8 bytes: sport + dport + seq (RFC 792 minimum)
_tcp_hdr_min = bytes(TCP(sport=tcp_src_two, dport=tcp_dst_one, seq=tcp_default_seq))[:8]
icmp4_err_revnat_min_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_node_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IPerror(src=v4_node_one, dst=v4_ext_one, flags="DF", proto=6) /
    Raw(_tcp_hdr_min)
)

# After revSNAT (min TCP): outer daddr -> pod_ip, inner saddr -> pod_ip
_tcp_hdr_min_after = bytes(TCP(sport=tcp_src_two, dport=tcp_dst_one, seq=tcp_default_seq))[:8]
icmp4_err_revnat_min_tcp_after = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IPerror(src=v4_pod_one, dst=v4_ext_one, flags="DF", proto=6) /
    Raw(_tcp_hdr_min_after)
)

icmp4_tcp_ingress = (
    Ether(src=mac_two, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_node_one) /
    TCP(sport=tcp_dst_one, dport=tcp_src_two) /
    Raw(default_data)
)

icmp4_tcp_ingress_post_revnat = (
    Ether(src=mac_two, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    TCP(sport=tcp_dst_one, dport=tcp_src_two) /
    Raw(default_data)
)

icmp4_err_nat_full_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_pod_one, dst=v4_ext_one) /
    ICMP(type="dest-unreach", code="communication-prohibited") /
    IPerror(bytes(icmp4_tcp_ingress_post_revnat[IP]))
)

icmp4_err_nat_full_tcp_after = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_node_one, dst=v4_ext_one) /
    ICMP(type="dest-unreach", code="communication-prohibited") /
    IPerror(bytes(icmp4_tcp_ingress[IP]))
)

# Shared header layers for the IPv6 egress flow, pre- and post-masquerade.
_ip6_hdr_egress = IPv6(src=v6_pod_one, dst=v6_ext_node_one)
_udp_hdr_egress = UDP(sport=tcp_src_two, dport=tcp_dst_one)

# Pod -> external host as goes into to-netdev host device (pre-masquerading).
# pod_ip6:33440 -> ext_ip6:22331
# Same idea as icmp4_err_revnat_egress_tcp: let the to-netdev datapath
# build the revSNAT state. 
icmp6_err_revnat_egress_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    _ip6_hdr_egress /
    _tcp_hdr_egress /
    Raw(default_data)
)

icmp6_err_revnat_egress_udp = (
    Ether(src=mac_one, dst=mac_two) /
    _ip6_hdr_egress /
    _udp_hdr_egress /
    Raw(default_data)
)

# Post-masquerade: saddr rewritten to node IP. Ports are unchanged because
# tcp_src_two (33440) > NODEPORT_PORT_MIN_NAT so the same source port is reused.
_ip6_hdr_egress_post = IPv6(src=v6_node_one, dst=v6_ext_node_one)
icmp6_err_revnat_egress_post_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    _ip6_hdr_egress_post /
    _tcp_hdr_egress /
    Raw(default_data)
)

icmp6_err_revnat_egress_post_udp = (
    Ether(src=mac_one, dst=mac_two) /
    _ip6_hdr_egress_post /
    _udp_hdr_egress /
    Raw(default_data)
)

def _icmp6_revnat_pkt(inner_l4):
    """Outer ICMPv6 PKT_TOO_BIG wrapper (pre-revSNAT): ext -> node, inner node -> ext."""
    return (
        Ether(src=mac_one, dst=mac_two) /
        IPv6(src=v6_ext_node_one, dst=v6_node_one) /
        ICMPv6PacketTooBig(mtu=1500) /
        _ip6_hdr_egress_post /
        inner_l4
    )

def _icmp6_revnat_after_pkt(inner_l4):
    """Outer ICMPv6 PKT_TOO_BIG wrapper (post-revSNAT): ext -> pod, inner pod -> ext."""
    return (
        Ether(src=mac_one, dst=mac_two) /
        IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
        ICMPv6PacketTooBig(mtu=1500) /
        _ip6_hdr_egress /
        inner_l4
    )

icmp6_err_revnat_full_tcp = _icmp6_revnat_pkt(
    _tcp_hdr_egress / Raw(default_data)
)

# After revSNAT: outer daddr -> pod_ip6, inner saddr -> pod_ip6. The ports are
# unchanged because the SNAT preserved the source port (see above).
icmp6_err_revnat_full_tcp_after = _icmp6_revnat_after_pkt(
    _tcp_hdr_egress / Raw(default_data)
)

icmp6_err_revnat_full_udp = _icmp6_revnat_pkt(
    _udp_hdr_egress / Raw(default_data)
)

icmp6_err_revnat_full_udp_after = _icmp6_revnat_after_pkt(
    _udp_hdr_egress / Raw(default_data)
)

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
