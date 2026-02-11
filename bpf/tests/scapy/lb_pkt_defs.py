# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

lb4_clusterip = (
    Ether(dst=mac_two, src=mac_one) /
    IP(src=v4_ext_one, dst=v4_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_svc_one) /
    Raw("S"*1)
)
