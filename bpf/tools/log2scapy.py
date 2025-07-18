#!/usr/bin/env python3

import sys
import re
import argparse
from scapy.all import *

def parse_pkts(filename: str):
    #TODO attempt to parse FILENAME:LINENUM if possible (HEXDUMP())
    #TODO parse timestamp
    pattern = re.compile(r"\s*(.*)\s*pkt\[(.*?)\]")

    pkts = []
    with open(filename, 'r') as f:
        for line in f:
            match = pattern.search(line)
            if not match:
                continue
            pkt = {}

            #TODO really improve context
            pkt["context"] = match.group(1)

            #TODO: support partial pkts (e.g. dump from IP on), needs context
            #on the trace
            pkt["scapy"] = Ether(bytes.fromhex(match.group(2)))
            pkts.append(pkt)
    return pkts

def dump_pkts(pkts):
    for pkt in pkts:
        print(f"{pkt['context']}")
        pkt["scapy"].show()
        print(f"")

def main():
    parser = argparse.ArgumentParser(description="Parse packets from a trace_pipe log.")
    parser.add_argument('filename', help="Log file to parse")
    parser.add_argument('-i', '--interactive', action='store_true', help="Open interactive Scapy shell with parsed packets.")
    parser.add_argument('-p', '--pcap', metavar='FILE', help="Write parsed packets to a pcap file")
    args = parser.parse_args()

    pkts = parse_pkts(args.filename)
    print(f"Parsed {len(pkts)} pkts...")

    if args.pcap:
        wrpcap(args.pcap, [pkt["scapy"] for pkt in pkts])
        print(f"Wrote {len(pkts)} packets to PCAP file '{args.pcap}'")

    print("")

    if args.interactive:
        import code
        local_vars = globals().copy()
        local_vars['pkts'] = pkts
        print("Opening Scapy shell. Inspect 'pkts'...")
        code.interact(local=local_vars)
    else:
        dump_pkts(pkts)

if __name__ == "__main__":
    main()
