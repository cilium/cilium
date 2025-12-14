# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

## IPv4 L2 announce (tc_l2_announcement.c)
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
