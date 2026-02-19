# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

# tc_redirect_lxc IPv4
tc_redirect_lxc_ipv4_pre = (
	Ether(src=mac_one, dst=mac_two) /
	IP(src=v4_pod_one, dst=v4_svc_one, id=0, ttl=64) /
	TCP(sport=tcp_src_one, dport=tcp_svc_one, seq=tcp_default_seq, window=tcp_default_win) /
	Raw(default_data)
)
tc_redirect_lxc_ipv4_post = (
	Ether(src=mac_three, dst=mac_four) /
	IP(src=v4_svc_loopback, dst=v4_pod_one, id=0, ttl=63) /
	TCP(sport=tcp_src_one, dport=tcp_dst_one, seq=tcp_default_seq, window=tcp_default_win) /
	Raw(default_data)
)

# tc_redirect_lxc IPv6
tc_redirect_lxc_ipv6_pre = (
	Ether(src=mac_one, dst=mac_two) /
	IPv6(src=v6_pod_one, dst=v6_svc_one, hlim=64) /
	TCP(sport=tcp_src_one, dport=tcp_svc_one, seq=tcp_default_seq, window=tcp_default_win) /
	Raw(default_data)
)
tc_redirect_lxc_ipv6_post = (
	Ether(src=mac_three, dst=mac_four) /
	IPv6(src=v6_svc_loopback, dst=v6_pod_one, hlim=63) /
	TCP(sport=tcp_src_one, dport=tcp_dst_one, seq=tcp_default_seq, window=tcp_default_win) /
	Raw(default_data)
)

# tc_redirect_host IPv4
tc_redirect_host_ipv4_pre = (
	Ether(src=mac_one, dst=mac_two) /
	IP(src=v4_ext_one, dst=v4_pod_one, id=0, ttl=64) /
	TCP(sport=tcp_src_one, dport=tcp_svc_one, seq=tcp_default_seq, window=tcp_default_win) /
	Raw(default_data)
)
tc_redirect_host_ipv4_post = (
	Ether(src=mac_three, dst=mac_four) /
	IP(src=v4_ext_one, dst=v4_pod_one, id=0, ttl=63) /
	TCP(sport=tcp_src_one, dport=tcp_svc_one, seq=tcp_default_seq, window=tcp_default_win) /
	Raw(default_data)
)

# tc_redirect_host IPv6
tc_redirect_host_ipv6_pre = (
	Ether(src=mac_one, dst=mac_two) /
	IPv6(src=v6_ext_node_one, dst=v6_pod_one, hlim=64) /
	TCP(sport=tcp_src_one, dport=tcp_svc_one, seq=tcp_default_seq, window=tcp_default_win) /
	Raw(default_data)
)
tc_redirect_host_ipv6_post = (
	Ether(src=mac_three, dst=mac_four) /
	IPv6(src=v6_ext_node_one, dst=v6_pod_one, hlim=63) /
	TCP(sport=tcp_src_one, dport=tcp_svc_one, seq=tcp_default_seq, window=tcp_default_win) /
	Raw(default_data)
)
