from scapy.all import *

from pkt_defs_common import *

## IPv6 ndp from netdev (ipv6_ndp_from_netdev_test.c)

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
