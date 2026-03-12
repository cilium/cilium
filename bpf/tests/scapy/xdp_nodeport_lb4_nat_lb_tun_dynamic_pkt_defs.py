# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

# XDP nodeport load balanced packet destined for a tunnel endpoint.
# In XDP this will be a packet that undergoes manual VXLAN header transform
# in eBPF.
#
# SRC - client IP : ephemeral port
# DST - node IP : nodeport service port
xdp_nodeport_lb4_nat_lb_tun_dynamic_pre = (
    Ether(src=mac_one, dst=host_mac_addr) /
    IP(src=v4_ext_one, dst=v4_svc_two) /
    TCP(sport=111, dport=tcp_svc_one) /
    Raw(default_data)
)

xdp_nodeport_lb4_nat_lb_tun_dynamic_post = (
    Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00") /
    IP(src="239.190.173.222", dst=v4_node_two, proto=17, id=0, len=110)
)
