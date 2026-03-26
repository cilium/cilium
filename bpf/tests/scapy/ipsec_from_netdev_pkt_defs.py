# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

## IPSec from netdev (decrypt_host.h)

v4_ipsec = (
    Ether(dst=mac_two, src=mac_one) /
    IP(src=v4_node_one, dst=v4_node_two) /
    ESP(spi=0x1, seq=1)
)

v6_ipsec = (
    Ether(dst=mac_two, src=mac_one) /
    IPv6(src=v6_node_one, dst=v6_node_two) /
    ESP(spi=0x1, seq=1)
)
