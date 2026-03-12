from scapy.all import *
from pkt_defs_common import *

tc_nodeport_lb4_nat_lb_dynamic_pre = (
    Ether(src=mac_one, dst=host_mac_addr) /
    IP(src=v4_ext_one, dst=v4_svc_two) /
    TCP(sport=111, dport=tcp_svc_one) /
    Raw(default_data)
)

tc_nodeport_lb4_nat_lb_dynamic_post = (
    Ether(src=mac_one, dst=host_mac_addr) /
    IP(src="239.190.173.222", dst=v4_pod_two, ttl=63) /
    TCP(sport=111, dport=tcp_svc_one) /
    Raw(default_data)
)
