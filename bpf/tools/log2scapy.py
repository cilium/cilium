#!/usr/bin/env python3

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

import sys
import re
import argparse
from scapy.all import *

def parse_pkts(filename: str) -> List[Dict]:
    """
    Parses packet hexdump log entries in the trace_pipe log.

    Expected hexdump log format:
       '(context) pkt_hex ((first_layer))[(bytes)]'
    Example:
       'bpftest.test-1515316 [001] b..11 102260.946440: bpf_trace_printk: tc_l2_announcement.c:93 no_entry: pkt_hex Ether[ffffffffffffdeadbeefdeef08060001080006040001deadbeefdeef6e000b01ffffffffffffac100a01]'

        context: bpftest.test-1515316 [001] b..11 102260.946440: bpf_trace_printk: tc_l2_announcement.c:93 no_entry:
        first_layer: Ether
        bytes: ffffffffffffdeadbeefdeef08060001080006040001deadbeefdeef6e000b01ffffffffffffac100a01
    """
    #TODO attempt to parse FILENAME:LINENUM if possible (HEXDUMP())
    #TODO parse timestamp
    pattern = re.compile(r"\s*(.*)\s*pkt_hex\s*(\w+)\[(.*?)\]")

    pkts = []
    with open(filename, 'r') as f:
        for line in f:
            match = pattern.match(line)
            if not match:
                continue
            pkt = {}

            #TODO Improve context by further parsing filenum etc
            pkt["context"] = match.group(1)

            try:
                s = f"{match.group(2)}({bytes.fromhex(match.group(3))})"
                pkt["scapy"] = eval(s)
            except Exception as e:
                print(f"Unable to parse: {line}")
                raise
            pkts.append(pkt)
    return pkts

def dump_pkts(pkts) -> None:
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
