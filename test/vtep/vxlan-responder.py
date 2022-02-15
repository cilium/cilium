#!/usr/bin/env python3
"""
SPDX-License-Identifier: Apache-2.0
Copyright Authors of Cilium

# vxlan-responder.py -h
usage: vxlan-responder.py [-h] [--dport UDPPORT] [--sport SRCPORT] [--vni VXLANVNI] [--outerip DSTHOST]
                          [--innerip INNERHOST] [--bridge BRIDGE]

optional arguments:
  -h, --help           show this help message and exit
  --dport UDPPORT      VXLAN UDP port
  --sport SRCPORT      UDP source port
  --vni VXLANVNI       VXLAN VNI value
  --outerip DSTHOST    Outer dst IP
  --innerip INNERHOST  Inner dst IP
  --bridge BRIDGE      Bridge interface to sniff
"""

import argparse
from scapy import all
from scapy.layers import all
from scapy.layers.inet import IP, ICMP, UDP
from scapy.packet import ls, Raw
from scapy.sendrecv import sniff, send
from scapy.all import *
PAYLOAD='zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'


def udp_monitor_callback(pkt):
    inLayer3 = pkt.payload.payload.payload.payload.payload

    if(pkt.haslayer(IP) and inLayer3.dst == INNERIP):
        print("incoming IP packet matches",  INNERIP)
        outLayer3 = pkt.payload
        udpLayer = pkt.payload.payload
        vxlanLayer = pkt.payload.payload.payload
        inLayer2 = pkt.payload.payload.payload.payload
        inLayer4 = pkt.payload.payload.payload.payload.payload.payload

        outerIP=IP(src=outLayer3.dst, dst=outLayer3.src)

        udpinfo=UDP(sport=SRCPORT, dport=UDPPORT)

        vxlan=VXLAN(flags=vxlanLayer.flags, vni=VNI)

        innerETH=Ether(dst=inLayer2.src, src=inLayer2.dst, type=0x800)

        innerIP=IP(src=inLayer3.dst,dst=inLayer3.src)

        innerICMP=ICMP(type=0, code=0, id=inLayer4.id, seq=inLayer4.seq)

        send(outerIP/udpinfo/vxlan/innerETH/innerIP/innerICMP/PAYLOAD)

    if(pkt.haslayer(ARP)):
        print("incoming ARP packet")

def dispatcher_callback(pkt):
    if(pkt.haslayer(UDP) and (pkt[UDP].dport == UDPPORT) and (pkt[IP].dst == DSTHOST)):
        print("incoming VXLAN packet")
        udp_monitor_callback(pkt)
    else:
        return

if __name__ == '__main__':

    global UDPPORT
    global SRCPORT
    global DSTHOST
    global INNERIP
    global VNI
    global BRIDGE

    parser = argparse.ArgumentParser()
    parser.add_argument("--dport", action="store", dest="udpport", type=int, help="VXLAN UDP port")
    parser.add_argument("--sport", action="store", dest="srcport", type=int, help="UDP source port")
    parser.add_argument("--vni", action="store", dest="vxlanvni", type=int, help="VXLAN VNI value")
    parser.add_argument("--outerip", action="store", dest="dsthost", help="Outer dst IP")
    parser.add_argument("--innerip", action="store", dest="innerhost", help="Inner dst IP")
    parser.add_argument("--bridge", action="store", dest="bridge", help="Bridge interface to sniff")
    args = parser.parse_args()

    if args.udpport:
        print("Destination port: % d" % args.udpport)
        UDPPORT=args.udpport

    if args.srcport:
        print("Source port: % d" % args.srcport)
        SRCPORT=args.srcport

    if args.vxlanvni:
        print("VXLAN VNI: % d" % args.vxlanvni)
        VNI=args.vxlanvni

    if args.dsthost:
        print("Destination IP: % s" % args.dsthost)
        DSTHOST=args.dsthost

    if args.innerhost:
        print("Inner destination IP as: % s" % args.innerhost)
        INNERIP=args.innerhost

    if args.bridge:
        print("Bridge interface: % s" % args.bridge)
        BRIDGE=args.bridge


    print("Scapy vxlan responder")
    scapy.all.conf.iface = BRIDGE
    sniff(filter=("port %s") % (UDPPORT), prn=dispatcher_callback)
