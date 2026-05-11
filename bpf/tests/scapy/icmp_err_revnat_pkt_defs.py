# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

# Pod -> external host as goes into to-netdev host device (pre-masquerading).
# pod_ip:33440 -> ext_ip:22331
# The intention is that this should setup the correct nat entries for
# testing revSNAT.
# We use tcp_src_two=33440 which is above the nodeport minimum default value
# meaning that, assuming a empty nat map, the SNAT mapping can reuse the same
# port.
icmp4_err_revnat_egress_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_pod_one, dst=v4_ext_one, flags="DF") /
    TCP(sport=tcp_src_two, dport=tcp_dst_one, seq=tcp_default_seq) /
    Raw(default_data)
)

# Full inner TCP header + complete data payload
icmp4_err_revnat_full_tcp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_node_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IPerror(src=v4_node_one, dst=v4_ext_one, flags="DF") /
    TCPerror(sport=tcp_src_two, dport=tcp_dst_one, seq=tcp_default_seq) /
    Raw(default_data)
)

# After revSNAT: outer daddr -> pod_ip, inner saddr -> pod_ip. The ports are
# unchanged because the SNAT preserved the source port (see above).
icmp4_err_revnat_full_tcp_after = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IPerror(src=v4_pod_one, dst=v4_ext_one, flags="DF") /
    TCPerror(sport=tcp_src_two, dport=tcp_dst_one, seq=tcp_default_seq) /
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
