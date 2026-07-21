# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *
from pkt_defs_common import *
from scapy.contrib.geneve import GENEVE, GeneveOptions

class IPOption_DSR(IPOption):
    name = "DSR IPv4 Option"

    fields_desc = [
        ByteField("option", 0x9a),
        ByteField("length", 8),
        ShortField("port", 0),
        IPField("addr", "0.0.0.0"),
    ]

    # Suppress trailing layer warnings when packed in IP option arrays
    def extract_padding(self, p):
        return b"", p

class IPv6Ext_DSR(Packet):
    name = "DSR IPv6 Ext Header"
    nh = 60

    fields_desc = [
        ByteField("nh", 6),
        ByteField("len", 2),

        ByteField("opt_type", 0x1b),
        ByteField("opt_len", 20),
        IP6Field("addr", "::"),
        ShortField("port", 0),
        ShortField("pad", 0)
    ]

bind_layers(IPv6, IPv6Ext_DSR, nh=60)
bind_layers(IPv6Ext_DSR, TCP, nh=6)

class Geneve_DSR_Opt4(GeneveOptions):
    name = "GENEVE DSR IPv4 Option"

    fields_desc = [
        ShortField("classid", 0x014b),
        ByteField("type", 0x81),
        BitField("reserved", 0, 3),
        BitField("length", 2, 5),

        IPField("addr", "0.0.0.0"),
        ShortField("port", 0),
        ShortField("pad", 0)
    ]

class Geneve_DSR_Opt6(GeneveOptions):
    name = "GENEVE DSR IPv6 Option"

    fields_desc = [
        ShortField("classid", 0x014b),
        ByteField("type", 0x81),
        BitField("reserved", 0, 3),
        BitField("length", 5, 5),

        IP6Field("addr", "::"),
        ShortField("port", 0),
        ShortField("pad", 0)
    ]

kpr_v4_dsr_lb1_syn = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_svc_one, flags="S")
)

kpr_v4_dsr_lb1_syn_post_option = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one, ttl=63,
       options=[bytes(IPOption_DSR(port=tcp_svc_one, addr=v4_svc_one))]) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="S")
)

kpr_v4_dsr_lb1_syn_post_option_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one, ttl=63,
       options=[bytes(IPOption_DSR(port=tcp_svc_one, addr=v4_svc_one))]) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="S")
)

kpr_v4_dsr_lb1_syn_post_geneve = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="S")
)

kpr_v4_dsr_lb1_syn_post_geneve_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_node_one, dst=v4_node_two, id=0, ttl=63) /
    UDP(sport=56602,dport=6081, chksum=0) /
    GENEVE(vni=2,proto=0x6558,
           options=[Geneve_DSR_Opt4(addr=v4_svc_one, port=tcp_svc_one)]) /
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="S")
)

kpr_v4_dsr_lb1_synack = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_svc_one, flags="SA")
)

kpr_v4_dsr_lb1_synack_post_option = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one, ttl=63) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="SA")
)

kpr_v4_dsr_lb1_synack_post_option_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one, ttl=63) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="SA")
)

kpr_v4_dsr_lb1_synack_post_geneve = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="SA")
)

kpr_v4_dsr_lb1_synack_post_geneve_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_node_one, dst=v4_node_two, id=0, ttl=63) /
    UDP(sport=56602, dport=6081, chksum=0) /
    GENEVE(vni=2,proto=0x6558) /
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="SA")
)

kpr_v4_dsr_lb2_data = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_svc_two, flags="") /
    b"foobar"
)

kpr_v4_dsr_lb2_data_post_option = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one, ttl=63,
       options=[bytes(IPOption_DSR(port=tcp_svc_two, addr=v4_svc_one))]) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v4_dsr_lb2_data_post_option_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one, ttl=63,
       options=[bytes(IPOption_DSR(port=tcp_svc_two, addr=v4_svc_one))]) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v4_dsr_lb2_data_post_geneve = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v4_dsr_lb2_data_post_geneve_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_node_one, dst=v4_node_two, id=0, ttl=63) /
    UDP(sport=24364,dport=6081, chksum=0) /
    GENEVE(vni=2,proto=0x6558,
           options=[Geneve_DSR_Opt4(addr=v4_svc_one, port=tcp_svc_two)]) /
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v4_dsr_lb2_data2_post_option = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one, ttl=63) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v4_dsr_lb2_data2_post_option_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one, ttl=63) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v4_dsr_lb2_data2_post_geneve_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_node_one, dst=v4_node_two, id=0, ttl=63) /
    UDP(sport=24364,dport=6081, chksum=0) /
    GENEVE(vni=2,proto=0x6558) /
    Ether(src=host_mac_addr, dst=mac_one) /
    IP(src=v4_ext_one, dst=v4_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v4_dsr_remote_node_reply = (
    Ether(src=mac_two, dst=mac_one) /
    IP(src=v4_pod_one, dst=v4_ext_one) /
    TCP(sport=tcp_dst_one, dport=tcp_src_one, flags="R")
)

kpr_v4_dsr_remote_node_reply_post = (
    Ether(src=mac_two, dst=mac_one) /
    IP(src=v4_svc_one, dst=v4_ext_one) /
    TCP(sport=tcp_svc_one, dport=tcp_src_one, flags="R")
)

kpr_v4_dsr_remote_node_data_option = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_ext_one, dst=v4_pod_one, ttl=63,
       options=[bytes(IPOption_DSR(port=tcp_svc_two, addr=v4_svc_one))]) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="") /
    b"foobar"
)

kpr_v4_dsr_remote_node_reply2_post = (
    Ether(src=mac_two, dst=mac_one) /
    IP(src=v4_svc_one, dst=v4_ext_one) /
    TCP(sport=tcp_svc_two, dport=tcp_src_one, flags="R")
)

kpr_v6_dsr_lb1_syn = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_svc_one, flags="S")
)

kpr_v6_dsr_lb1_syn_post_option = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one, nh=60) /
    IPv6Ext_DSR(addr=v6_svc_one, port=tcp_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="S", chksum=50277)
)

kpr_v6_dsr_lb1_syn_post_option_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one, nh=60) /
    IPv6Ext_DSR(addr=v6_svc_one, port=tcp_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="S", chksum=50277)
)

kpr_v6_dsr_lb1_syn_post_geneve = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="S")
)

kpr_v6_dsr_lb1_syn_post_geneve_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_node_one, dst=v4_node_two, id=0) /
    UDP(sport=52625,dport=6081, chksum=0) /
    GENEVE(vni=2,proto=0x6558,
           options=[Geneve_DSR_Opt6(addr=v6_svc_one, port=tcp_svc_one)]) /
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="S")
)

kpr_v6_dsr_lb1_synack = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_svc_one, flags="SA")
)

kpr_v6_dsr_lb1_synack_post_option = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="SA")
)

kpr_v6_dsr_lb1_synack_post_option_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="SA")
)

kpr_v6_dsr_lb1_synack_post_geneve = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="SA")
)

kpr_v6_dsr_lb1_synack_post_geneve_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_node_one, dst=v4_node_two, id=0) /
    UDP(sport=52625, dport=6081, chksum=0) /
    GENEVE(vni=2,proto=0x6558) /
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="SA")
)

kpr_v6_dsr_lb2_data = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_svc_one) /
    TCP(sport=tcp_src_one, dport=tcp_svc_two, flags="") /
    b"foobar"
)

kpr_v6_dsr_lb2_data_post_option = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one, nh=60) /
    IPv6Ext_DSR(addr=v6_svc_one, port=tcp_svc_two) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="", chksum=25015) /
    b"foobar"
)

kpr_v6_dsr_lb2_data_post_option_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one, nh=60) /
    IPv6Ext_DSR(addr=v6_svc_one, port=tcp_svc_two) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="", chksum=25015) /
    b"foobar"
)

kpr_v6_dsr_lb2_data_post_geneve = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v6_dsr_lb2_data_post_geneve_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_node_one, dst=v4_node_two, id=0) /
    UDP(sport=18056,dport=6081, chksum=0) /
    GENEVE(vni=2,proto=0x6558,
           options=[Geneve_DSR_Opt6(addr=v6_svc_one, port=tcp_svc_two)]) /
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v6_dsr_lb2_data2_post_option = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v6_dsr_lb2_data2_post_option_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v6_dsr_lb2_data2_post_geneve_xdp = (
    Ether(src=mac_one, dst=mac_two) /
    IP(src=v4_node_one, dst=v4_node_two, id=0) /
    UDP(sport=18056,dport=6081, chksum=0) /
    GENEVE(vni=2,proto=0x6558) /
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one) /
    TCP(sport=tcp_src_one, dport=tcp_dst_two, flags="") /
    b"foobar"
)

kpr_v6_dsr_remote_node_reply = (
    Ether(src=mac_two, dst=mac_one) /
    IPv6(src=v6_pod_one, dst=v6_ext_node_one) /
    TCP(sport=tcp_dst_one, dport=tcp_src_one, flags="R")
)

kpr_v6_dsr_remote_node_reply_post = (
    Ether(src=mac_two, dst=mac_one) /
    IPv6(src=v6_svc_one, dst=v6_ext_node_one) /
    TCP(sport=tcp_svc_one, dport=tcp_src_one, flags="R")
)

kpr_v6_dsr_remote_node_data_option = (
    Ether(src=host_mac_addr, dst=mac_one) /
    IPv6(src=v6_ext_node_one, dst=v6_pod_one, nh=60) /
    IPv6Ext_DSR(addr=v6_svc_one, port=tcp_svc_two) /
    TCP(sport=tcp_src_one, dport=tcp_dst_one, flags="", chksum=25015) /
    b"foobar"
)

kpr_v6_dsr_remote_node_reply2_post = (
    Ether(src=mac_two, dst=mac_one) /
    IPv6(src=v6_svc_one, dst=v6_ext_node_one) /
    TCP(sport=tcp_svc_two, dport=tcp_src_one, flags="R")
)
