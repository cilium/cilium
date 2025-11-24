# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

## IPv6 L2 announce (tc_l2_announcement6.c)

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
