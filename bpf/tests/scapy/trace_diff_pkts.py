#!/usr/bin/env python3

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

import argparse
import re
import sys

from scapy.all import *

def parse_asserts(filename: str) -> List[Dict]:
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
