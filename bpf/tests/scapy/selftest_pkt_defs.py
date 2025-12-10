# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

## Scapy self tests (_scapy_selftest.c)
sst_req = (
    Ether(dst=mac_bcast, src=mac_one) /
    ARP(op="who-has", psrc=v4_ext_one, pdst=v4_svc_one, \
        hwsrc=mac_one, hwdst=mac_bcast)
)

sst_rep = (
    Ether(dst=mac_one, src=mac_two) /
    ARP(op="is-at", psrc=v4_svc_one, pdst=v4_ext_one, \
        hwsrc=mac_two, hwdst=mac_one)
)

# Padded reply to test
sst_rep_pad = (
    Ether(dst=mac_one, src=mac_two) /
    ARP(op="is-at", psrc=v4_svc_one, pdst=v4_ext_one, \
        hwsrc=mac_two, hwdst=mac_one) /
    Raw("A"*8)
)

assert len(bytes(sst_rep_pad)) == (len(bytes(sst_rep)) + 8)
