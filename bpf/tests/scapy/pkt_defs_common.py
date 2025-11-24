# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

# Note: these replicate pktgen.h values
# TODO: it would be ideal to have a single source of truth for these values

# MAC addresses
mac_one   = "DE:AD:BE:EF:DE:EF"
mac_two   = "13:37:13:37:13:37"
mac_three = "31:41:59:26:35:89"
mac_four  = "0D:1D:22:59:A9:C2"
mac_five  = "15:21:39:45:4D:5D"
mac_six   = "08:14:1C:32:52:7E"
mac_zero  = "00:00:00:00:00:00"
mac_bcast = "FF:FF:FF:FF:FF:FF"
host_mac_addr = "CE:72:A7:03:88:56"

# IPv4 addresses for hosts, external to the cluster
v4_ext_one   = "110.0.11.1"
v4_ext_two   = "120.0.12.2"
v4_ext_three = "130.0.13.3"

# IPv4 addresses for nodes in the cluster
v4_node_one   = "10.0.10.1"
v4_node_two   = "10.0.10.2"
v4_node_three = "10.0.10.3"

# IPv4 addresses for services in the cluster
v4_svc_one   = "172.16.10.1"
v4_svc_two   = "172.16.10.2"
v4_svc_three = "172.16.10.3"

# IPv4 addresses for pods in the cluster
v4_pod_one    = "192.168.0.1"
v4_pod_two    = "192.168.0.2"
v4_pod_three  = "192.168.0.3"

#Node-specific PodCIDR
v4_pod_cidr_on_node_two  = "192.168.1.0"
v4_pod_one_on_node_two   = "192.168.1.1"
v4_pod_two_on_node_two   = "192.168.1.2"
v4_pod_three_on_node_two = "192.168.1.3"

v4_pod_cidr_size = 24

v4_svc_loopback = "10.245.255.31"

v4_all = "0.0.0.0"

# IPv6 addresses for pods in the cluster
v6_pod_one   = "fd04::1"
v6_pod_two   = "fd04::2"
v6_pod_three = "fd04::3"

# IPv6 addresses for nodes in the cluster
v6_node_one   = "fd05::1"
v6_node_two   = "fd05::2"
v6_node_three = "fd05::3"

# IPv6 addresses for services in the cluster
v6_svc_one    = "fd10::1"

# External IPv6 addrs
v6_ext_node_one = "2001::1"

v6_all = "::"

# Source port to be used by a client
tcp_src_one   = 22330
tcp_src_two   = 33440
tcp_src_three = 44550

tcp_dst_one   = 22331
tcp_dst_two   = 33441
tcp_dst_three = 44551

tcp_svc_one   = 80
tcp_svc_two   = 443
tcp_svc_three = 53

default_data = "Should not change!!"

# Utility functions
def v6_get_ns_addr(v6_addr:str) -> str:
    addr_bytes = in6_getnsma(inet_pton(socket.AF_INET6, v6_addr))
    return inet_ntop(socket.AF_INET6, addr_bytes)

def v6_get_ns_mac(v6_addr:str) -> str:
    addr_bytes = in6_getnsma(inet_pton(socket.AF_INET6, v6_addr))
    return in6_getnsmac(addr_bytes)
