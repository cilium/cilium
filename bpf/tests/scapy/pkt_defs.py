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

# Test packet/buffer definitions

## IPv6 ndp from netdev
### Pod NS/NA
v6_ndp_pod_ns = (
    Ether(dst=mac_two, src=mac_one) /
    IPv6(dst=v6_pod_two, src=v6_pod_one, hlim=255) /
    ICMPv6ND_NS(tgt=v6_pod_three)
)

v6_ndp_pod_ns_llopt = (
    v6_ndp_pod_ns /
    ICMPv6NDOptSrcLLAddr(lladdr="01:01:01:01:01:01")
)

v6_ndp_pod_na_llopt = (
    Ether(dst=mac_one, src=mac_two) /
    IPv6(dst=v6_pod_one, src=v6_pod_three, hlim=255) /
    ICMPv6ND_NA(R=0, S=1, O=1, tgt=v6_pod_three) /
    ICMPv6NDOptDstLLAddr(lladdr=mac_two)
)

v6_ndp_pod_ns_mmac = v6_get_ns_mac(v6_pod_three)
v6_ndp_pod_ns_ma = v6_get_ns_addr(v6_pod_three)
assert(v6_ndp_pod_ns_mmac == '33:33:ff:00:00:03')
assert(v6_ndp_pod_ns_ma == 'ff02::1:ff00:3')

v6_ndp_pod_ns_mcast = (
    Ether(dst=v6_ndp_pod_ns_mmac, src=mac_one) /
    IPv6(dst=v6_ndp_pod_ns_ma, src=v6_pod_one, hlim=255) /
    ICMPv6ND_NS(tgt=v6_pod_three)
)

v6_ndp_pod_ns_mcast_llopt = (
    v6_ndp_pod_ns_mcast /
    ICMPv6NDOptSrcLLAddr(lladdr="01:01:01:01:01:01")
)

### Node NS/NA
v6_ndp_node_ns = (
    Ether(dst=mac_two, src=mac_one) /
    IPv6(dst=v6_pod_two, src=v6_pod_one, hlim=255) /
    ICMPv6ND_NS(tgt=v6_node_one)
)

v6_ndp_node_ns_llopt = (
    v6_ndp_node_ns /
    ICMPv6NDOptSrcLLAddr(lladdr="01:01:01:01:01:01")
)

v6_ndp_node_ns_mmac = v6_get_ns_mac(v6_node_one)
v6_ndp_node_ns_ma = v6_get_ns_addr(v6_node_one)
assert(v6_ndp_node_ns_mmac == '33:33:ff:00:00:01')
assert(v6_ndp_node_ns_ma == 'ff02::1:ff00:1')

v6_ndp_node_ns_mcast = (
    Ether(dst=v6_ndp_node_ns_mmac, src=mac_one) /
    IPv6(dst=v6_ndp_node_ns_ma, src=v6_pod_one, hlim=255) /
    ICMPv6ND_NS(tgt=v6_node_one)
)

v6_ndp_node_ns_mcast_llopt = (
    v6_ndp_node_ns_mcast /
    ICMPv6NDOptSrcLLAddr(lladdr="01:01:01:01:01:01")
)

## L2 announce (v4)
l2_announce_arp_req = (
    Ether(dst=mac_bcast, src=mac_one) /
    ARP(op="who-has", psrc=v4_ext_one, pdst=v4_svc_one, \
        hwsrc=mac_one, hwdst=mac_bcast)
)

l2_announce_arp_reply = (
    Ether(dst=mac_one, src=mac_two) /
    ARP(op="is-at", psrc=v4_svc_one, pdst=v4_ext_one, \
        hwsrc=mac_two, hwdst=mac_one)
)

## L2 announce (v6)

### Calculate the IPv6 NS solicitation address
l2_announce6_ns_mmac = v6_get_ns_mac(v6_svc_one)
l2_announce6_ns_ma = v6_get_ns_addr(v6_svc_one)
assert(l2_announce6_ns_mmac == '33:33:ff:00:00:01')
assert(l2_announce6_ns_ma == 'ff02::1:ff00:1')

l2_announce6_ns = (
    Ether(dst=l2_announce6_ns_mmac, src=mac_one) /
    IPv6(src=v6_ext_node_one, dst=l2_announce6_ns_ma, hlim=255) /
    ICMPv6ND_NS(tgt=v6_svc_one) /
    ICMPv6NDOptSrcLLAddr(lladdr=mac_one)
)

l2_announce6_targeted_ns = (
    Ether(dst=mac_two, src=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_svc_one, hlim=255) /
    ICMPv6ND_NS(tgt=v6_svc_one) /
    ICMPv6NDOptSrcLLAddr(lladdr=mac_one)
)

l2_announce6_na = (
    Ether(dst=mac_one, src=mac_two) /
    IPv6(src=v6_svc_one, dst=v6_ext_node_one, hlim=255) /
    ICMPv6ND_NA(R=0, S=1, O=1, tgt=v6_svc_one) /
    ICMPv6NDOptDstLLAddr(lladdr=mac_two)
)
