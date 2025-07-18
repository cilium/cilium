import os
import re
import sys
import jinja2

from scapy.all import *
from pkt_constants import *

# Match SCAPY_BUF(name, ...
PKT_REGEX = re.compile(
    r'SCAPY_DEF_BUF\(\s*([A-Za-z0-9_]+)\s*,\s*(.+?)\s*$',
    re.DOTALL | re.MULTILINE
)

def find_buf_refs(filepath: str, bufs: dict[str, str]) -> None:
    """Parse one file and extract SCAPY_BUF(name, varargs as single string)."""

    try:
        if filepath.endswith("scapy.h"):
            return
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            matches = PKT_REGEX.findall(f.read())
            for match in matches:
                if len(match) != 2:
                    raise Exception(f"Unable to parse {match}")

                name = match[0].strip()
                scapy_buf = match[1].strip().replace("\n", "")
                # Remove trailing );
                scapy_buf = re.sub(r'\s*\)\s*;\s*$', '', scapy_buf)
                if name in bufs and scapy_buf != bufs[name]:
                    raise Exception(f"Mismatching packet definitions with name '{name}'; found '{scapy_buf}' and '{bufs[name]}'")
                buf = eval(scapy_buf)
                bufs[name] = {
                    "str": scapy_buf,
                    "buf": buf,
                    "bytes": [f"0x{b:02x}" for b in list(bytes(buf))]
                }
    except Exception as e:
        print(f"[ERROR] Unable to read {filepath}: {e}", file=sys.stderr)
        raise e

def scan_dir(dir_name: str):
    """Recursively scan .h/.c files and return map of name => flat varargs string."""
    bufs = {}
    for d, _, files in os.walk(dir_name):
        for file in files:
            if not file.endswith('.h') and not file.endswith('.c'):
                continue
            find_buf_refs(os.path.join(d, file), bufs)
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
