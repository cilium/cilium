#!/usr/bin/env python3

import sys
import re
from scapy.all import *

def parse_asserts():
    pattern = re.compile(r"bpf_trace_printk: (\S+):(\d+)\s+assert\s*'([^']+)'\s+FAILED!\s+(Got|Expected)[^:]*:\s*pkt\[(.*?)\]")

    asserts = {}
    for line in sys.stdin:
        match = pattern.search(line)
        if not match:
            continue

        name = match.group(3)
        kind = match.group(4)

        if name not in asserts:
            asserts[name] = {}
        asserts[name]["file"] = match.group(1)
        asserts[name]["linenum"] = match.group(2)

        if "Got" in kind:
            asserts[name]['got'] = match.group(5)
        elif "Expected" in kind:
            asserts[name]['expected'] = match.group(5)
        else:
            raise Exception("Unknown error")
    return asserts

def main():
    asserts = parse_asserts()
    for name, data in asserts.items():
        print(f"=== Start {data['file']}:{data['linenum']} '{name}' ===")
        expected = Ether(bytes.fromhex(data["expected"]))
        got = Ether(bytes.fromhex(data["got"]))
        print(f"--- Expected ---")
        expected.show()
        print(f"--- Got ---")
        got.show()
        print(f"===  End  {data['file']}:{data['linenum']} '{name}' ===")

if __name__ == "__main__":
    main()
