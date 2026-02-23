#!/usr/bin/env python3

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

import os
import re
import sys
import jinja2

from scapy.all import *
from pkt_defs import *

# Match BUF_DECL(name, ...)
PKT_REGEX = re.compile(
    r'^\s*BUF_DECL\(\s*([A-Za-z0-9_]+)\s*,\s*(.+?)\s*$',
    re.DOTALL | re.MULTILINE
)

def find_buf_refs(filepath: str, bufs: dict[str, dict]) -> dict[str, dict]:
    """Parse one file and extract BUF_DECL(name, varargs as single string)."""

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        matches = PKT_REGEX.findall(f.read())
        for match in matches:
            if len(match) != 2:
                raise Exception(f"Unable to parse {match}")

            name = match[0].strip()
            scapy_buf = match[1].strip().replace("\n", "")

            # Remove trailing );
            scapy_buf = re.sub(r'\s*\)\s*;\s*$', '', scapy_buf)

            try:
                buf = eval(scapy_buf)
            except Exception as e:
                raise Exception(f"Unknown scapy buffer '{scapy_buf}'. Please make sure it's defined under scapy/*_pkt_defs.py")

            if name in bufs and buf != bufs[name]["buf"]:
                raise Exception(f"Mismatching packet definitions with name '{name}'; found '{scapy_buf}' and '{bufs[name]}'.")

            bufs[name] = {
                "str": scapy_buf,
                "buf": buf,
                "bytes": [f"0x{b:02x}" for b in list(bytes(buf))]
            }
    return bufs

def scan_dir(dir_name: str) -> dict[str, dict]:
    """Recursively scan .h/.c files and return map of name => flat varargs string."""
    bufs = {}

    with os.scandir(dir_name) as it:
        for entry in it:
            if entry.is_dir(follow_symlinks=False):
                # Implement recursion if tests are in subdirs
                continue

            if not entry.name.endswith(('.h', '.c')) or entry.name == "scapy.h":
                continue

            try:
                bufs = find_buf_refs(entry.path, bufs)
            except Exception as e:
                print(f"[ERROR] Unable to read {entry.path}: {e}", file=sys.stderr)
                raise
    return bufs

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory_to_scan>")
        sys.exit(1)

    dir = sys.argv[1]
    if not os.path.isdir(dir):
        print(f"[ERROR] Invalid directory: {directory_to_scan}")
        sys.exit(1)

    bufs = scan_dir(dir)

    template = """\
#pragma once

/**
* This is an auto-generated header containing byte arrays of the scapy
* buffer definitions.
*/

{% for name, packet in bufs.items() -%}
#define __SCAPY_BUF_{{ name }}_BYTES {{"{"}}{{ bufs[name]["bytes"]|join(', ') -}}{{"}"}}
{% endfor %}
    """
    s = jinja2.Template(template).render(bufs=bufs)
    print(s)
