#!/usr/bin/env python3

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import re
import sys

from scapy.all import *

def parse_asserts():
    try:
        asserts = json.load(sys.stdin)
    except Exception as e:
        print(f"ERROR: unable to parse JSON serialized asserts {e}")
        raise e
    return asserts

def bytes_to_scapy_pkt(first_layer, hex_str):
    try:
        s = f"{first_layer}({bytes.fromhex(hex_str)})"
        return eval(s)
    except Exception as e:
        print(f"ERROR: unable generate scapy Packet from '{hex_str}': {e}")
        raise e

def pkt_to_dict(pkt: Packet) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    current_layer = pkt

    current_layer_str = ""
    while current_layer:
        layer_name = current_layer.__class__.__name__
        current_layer_str += f"[ {layer_name} ]"
        for field_name, field_value in current_layer.fields.items():
            key = f"{current_layer_str}.{field_name}"
            result[key] = field_value
        current_layer = current_layer.payload
        if not isinstance(current_layer, Packet):
            break

    return result

def diff_pkts(expected: Packet, got: Packet) -> None:
    pkt1 = pkt_to_dict(expected)
    pkt2 = pkt_to_dict(got)

    remove = {}
    add = {}

    for key in pkt1:
        if key in pkt2:
            if pkt1[key] == pkt2[key]:
                continue
            else:
                remove[key] = pkt1[key]
                add[key] = pkt2[key]
        else:
            remove[key] = pkt1[key]
    for key in pkt2:
        if key in pkt1:
            continue
        add[key] = pkt2[key]

    # Print diff
    for key in remove:
        print(f"  - {key}: {str(remove[key])}")
        if key in add:
            print(f"  + {key}: {str(add[key])}")
            add.pop(key)
    for key in add:
            print(f"  + {key}: {str(add[key])}")

def main():
    asserts = parse_asserts()

    for elem in asserts:
        exp = bytes_to_scapy_pkt(elem["first-layer"], elem["exp-buf"])
        got = bytes_to_scapy_pkt(elem["first-layer"], elem["got-buf"])

        print(f"=== START {elem['file']}:{elem['linenum']} '{elem['name']}' ===")
        print(f">>> Expected (len: {len(elem['exp-buf'])} bytes) <<<")
        exp.show()
        print(f">>> Got (len: {len(elem['got-buf'])} bytes) <<<")
        got.show()

        # Show pseudo-diff
        print(f">>> Diff <<<")
        print(f"  --- a/pkt (Expected)")
        print(f"  +++ b/pkt (Got)\n")
        diff_pkts(exp, got)

        print(f"\n=== END {elem['file']}:{elem['linenum']} '{elem['name']}' ===")

if __name__ == "__main__":
    main()
