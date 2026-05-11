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
