from scapy.all import *
from pkt_defs_common import *

tc_nodeport_lb6_nat_lb_dynamic_pre = (
    Ether(src=mac_one, dst=host_mac_addr) /
    IPv6(src=v6_ext_node_one, dst=v6_svc_one) /
    TCP(sport=111, dport=tcp_svc_one) /
    Raw(default_data)
)

tc_nodeport_lb6_nat_lb_dynamic_post = (
    Ether(src=mac_one, dst=host_mac_addr) /
    IPv6(src="dead::1", dst=v6_pod_two, hlim=63) /
    TCP(sport=111, dport=tcp_svc_one) /
    Raw(default_data)
)
