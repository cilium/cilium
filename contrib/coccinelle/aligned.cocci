// SPDX-License-Identifier: GPL-2.0
/// Find cases of missing __align_stack_8. On-the-stack objects of size > 8
/// bytes must be force-aligned when 8 bytes isn't their natural object
/// alignment (e.g., __u8 foo[12]).
///
/// Coccinelle v1.0.7 is needed to handle the presence of #pragma unrolls in
/// our code.
// Confidence: Medium
// Copyright Authors of Cilium.
// Comments:
// Options: --include-headers

@initialize:python@
@@

cnt = 0


@rule disable optional_attributes@
attribute name __align_stack_8;
expression e1, e2;
identifier x;
position p;
@@

(
  struct \(icmphdr\|icmp6hdr\|ipv6_opt_hdr\|dsr_opt_v6\) x@p
+ __align_stack_8
  ;
|
  struct \(icmphdr\|icmp6hdr\|ipv6_opt_hdr\|dsr_opt_v6\) x@p
+ __align_stack_8
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
|
  memcmp(e1, &x, ...)
|
  memcmp(&x, e1, ...)
)


@script:python@
x << rule.x;
p << rule.p;
@@

print("* file %s: missing __align_stack_8 on %s on line %s" % (p[0].file, x, p[0].line))
cnt += 1


@finalize:python@
@@

if cnt > 0:
  print("""Use the following command to fix the above issues:
docker run --rm --user 1000 --workdir /workspace -v `pwd`:/workspace \\
    -e COCCINELLE_HOME=/usr/local/lib/coccinelle \\
    -it docker.io/cilium/coccicheck:2.4@sha256:24abe3fbb8e829fa41a68a3b76cb4df84fd5a87a7d1d6254c1c1fe5effb5bd1b \\
    spatch --include-headers --very-quiet --in-place bpf/ \\
    --sp-file contrib/coccinelle/aligned.cocci\n
""")
