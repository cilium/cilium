// SPDX-License-Identifier: GPL-2.0
/// Find cases of missing __align_stack_8. On-the-stack objects of size > 8
/// bytes must be force-aligned when 8 bytes isn't their natural object
/// alignment (e.g., __u8 foo[12]).
///
/// Coccinelle v1.0.7 is needed to handle the presence of #pragma unrolls in
/// our code.
// Confidence: Medium
// Copyright (C) 2020 Authors of Cilium.
// Comments:
// Options: --include-headers

@rule@
expression e1, e2;
identifier x;
position p;
@@

(
  struct \(icmphdr\|icmp6hdr\|ipv6_opt_hdr\|dsr_opt_v6\) x@p
  ;
|
  struct \(icmphdr\|icmp6hdr\|ipv6_opt_hdr\|dsr_opt_v6\) x@p
  = ...;
)
  // We want to match the above declaration if there *exists* even one path
  // that leads from the variable declaration to its use in one of the
  // functions below.
  ... when exists
(
  ctx_load_bytes(e1, e2, &x, ...)
|
  ctx_store_bytes(e1, e2, &x, ...)
|
  memcpy(e1, &x, ...)
)


@script:python@
x << rule.x;
p << rule.p;
@@

print "* file %s: missing __align_stack_8 on %s on line %s" % (p[0].file, x, p[0].line)
