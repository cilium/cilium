// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium.
/// Detect any usage of hexdump() function calls and HEXDUMP() MACROs, including
/// suffixed variants. Also the inclusion of 'hexdump.h'. All of these should
/// be avoided in production code.
// Confidence: Medium
// Options: --include-headers

@check_hexdump_call@
expression args;
identifier f;
position p;
@@

f@p(args, ...);

@script:python@
p << check_hexdump_call.p;
f << check_hexdump_call.f;
@@

import re

if (
    re.match(r"^(hexdump|HEXDUMP)", f)
    and not p[0].file.endswith("lib/hexdump.h")
    and "tests/" not in p[0].file
):
    print("* file %s: %s() used on line %s. Remove hexdump/HEXDUMP calls in production code!" % (p[0].file, f, p[0].line))

@check_hexdump_include@
expression f;
position p;
@@

#include f@p

@script:python@
f << check_hexdump_include.f;
p << check_hexdump_include.p;
@@

import re

if "hexdump.h" in f and "tests/" not in p[0].file:
    print("* file %s: hexdump.h included on line %s. Do not include 'hexdump.h' in production code" % (p[0].file, p[0].line))
