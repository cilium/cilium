#!/usr/bin/env python3

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

import argparse
import re
import sys

from scapy.all import *

def parse_asserts(filename: str) -> List[Dict]:
    """
    Parses asserts in the log file.

    Expected assert log format:
       '... bpf_trace_printk: (file):(linenum) assert '(assert_name)' FAILED! (Got|Expected) ... : pkt_hex \((first_layer)\)[(bytes)]'
    Example:
       'bpftest.test-1515316 [001] b..11 102260.946507: bpf_trace_printk: tc_l2_announcement.c:164 assert 'arp_rep_only_ok' FAILED! Got (ctx): pkt_hex ARP[0001080006040002133713371337ac100a01deadbeefdeef6e000b01]'

        file: tc_l2_announcement.c
        linenum: 164
        assert_name: arp_rep_only_ok
        Got|Expected: Got
        first_layer: Ether
        bytes: 0001080006040002133713371337ac100a01deadbeefdeef6e000b01
    """
    pattern = re.compile(r"\s*.*bpf_trace_printk: (\S+):(\d+)\s+assert\s*'([^']+)'\s+FAILED!\s+(Got|Expected)[^:]*:\s*pkt_hex\s*(\w+)\[(.*?)\]")

    asserts = {}
    with open(filename, 'r') as f:
        for line in f:
            match = pattern.match(line)
            if not match:
                continue

            name = match.group(3)
            kind = match.group(4)

            if name not in asserts:
                asserts[name] = {}
            asserts[name]["file"] = match.group(1)
            asserts[name]["linenum"] = match.group(2)

            s = f"{match.group(5)}({bytes.fromhex(match.group(6))})"
            asserts[name][kind.lower().strip()] = eval(s)
    return asserts

def main():
    parser = argparse.ArgumentParser(description="Parse failed assertions from a trace_pipe log file.")
    parser.add_argument('filename', help="Log file to parse")

    args = parser.parse_args()
    asserts = parse_asserts(args.filename)

    for name, data in asserts.items():
        print(f"=== Start {data['file']}:{data['linenum']} '{name}' ===")
        print(f"--- Expected ---")
        asserts[name]["expected"].show()
        print(f"--- Got ---")
        asserts[name]["got"].show()
        print(f"===  End  {data['file']}:{data['linenum']} '{name}' ===")

        #TODO add a more specific diff (patch-style diff?)

if __name__ == "__main__":
    main()
