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


# NodePort LB4 RevDNAT ICMP error scenario:
# Backend (mac_five, v4_pod_two) sends ICMP Frag Needed to LB (host_mac_addr, v4_node_one)
# complaining about the SNATed request (LB_IP:NODEPORT_PORT_MIN_NAT -> backend).
nodeport_lb4_icmp_error_before = (
    Ether(src=mac_five, dst=host_mac_addr) /
    IP(src=v4_pod_two, dst=v4_node_one, ttl=64) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IP(src=v4_node_one, dst=v4_pod_two, ttl=64, flags="DF") /
    TCP(sport=32768, dport=8080, seq=tcp_default_seq, flags="S")
)


# After RevDNAT: ICMP error should target the original client (v4_ext_one:111 -> v4_svc_two:80).
nodeport_lb4_icmp_error_after = (
    Ether(src=mac_five, dst=host_mac_addr) /
    IP(src=v4_svc_two, dst=v4_ext_one, ttl=63) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IP(src=v4_ext_one, dst=v4_svc_two, ttl=64, flags="DF") /
    TCP(sport=111, dport=tcp_svc_one, seq=tcp_default_seq, flags="S")
)


# DSR backend node ICMP error RevDNAT scenario:
# Backend node (mac_three, v4_pod_one) sends ICMP Frag Needed to client (mac_one, v4_ext_one),
# referencing the original request (v4_ext_one:111 -> v4_pod_one:8080).
dsr_backend_icmp4_err_before = (
    Ether(src=mac_three, dst=mac_one) /
    IP(src=v4_pod_one, dst=v4_ext_one, ttl=64) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IP(src=v4_ext_one, dst=v4_pod_one, ttl=64, flags="DF") /
    TCP(sport=111, dport=8080, seq=tcp_default_seq, flags="S")
)

# After RevDNAT: outer src BACKEND_IP -> FRONTEND_IP, inner dst BACKEND_IP:8080 -> FRONTEND_IP:80.
dsr_backend_icmp4_err_after = (
    Ether(src=mac_three, dst=mac_one) /
    IP(src=v4_svc_one, dst=v4_ext_one, ttl=64) /
    ICMP(type=3, code=4, nexthopmtu=1500) /
    IP(src=v4_ext_one, dst=v4_svc_one, ttl=64, flags="DF") /
    TCP(sport=111, dport=tcp_svc_one, seq=tcp_default_seq, flags="S")
)
