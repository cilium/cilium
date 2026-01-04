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