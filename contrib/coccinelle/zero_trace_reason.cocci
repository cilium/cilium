// SPDX-License-Identifier: GPL-2.0
/// Prevent passing 0 as a reason to send_trace_notify(), because 0 is a valid
/// value corresponding to new conntrack connections, and passing it instead of
/// TRACE_REASON_UNKNOWN may confuse Hubble.
// Confidence: Medium
// Copyright Authors of Cilium.
// Comments:
// Options: --include-headers

@initialize:python@
@@

cnt = 0


@pass_reason@
expression e1, e2, e3, e4, e5, e6, e7, e8;
identifier f;
position p;
@@

(
  send_trace_notify@f(e1, e2, e3, e4, e5, e6,
- 0@p,
+ TRACE_REASON_UNKNOWN,
  e7);
|
  \(send_trace_notify4@f\|send_trace_notify6@f\)(e1, e2, e3, e4, e5, e6, e7,
- 0@p,
+ TRACE_REASON_UNKNOWN,
  e8);
|
  update_trace_metrics@f(e1, e2,
- 0@p
+ TRACE_REASON_UNKNOWN
  );
)


@script:python@
p << pass_reason.p;
f << pass_reason.f;
@@

print("* file %s: %s() has '0' as trace reason on line %s, use enum trace_reason instead (TRACE_REASON_UNKNOWN if the reason is not known)" % (p[0].file, f, p[0].line))
cnt += 1


@declare_ctx@
identifier tc;
position p;
@@

(
  struct trace_ctx tc = {
-   .reason = 0@p,
+   .reason = TRACE_REASON_UNKNOWN,
    ...
  };
|
  struct trace_ctx tc;
  ... when != return ...;
- tc.reason = 0@p;
+ tc.reason = TRACE_REASON_UNKNOWN;
|
  struct trace_ctx *tc;
  ... when != return ...;
- tc->reason = 0@p;
+ tc->reason = TRACE_REASON_UNKNOWN;
)


@script:python@
p << declare_ctx.p;
tc << declare_ctx.tc;
@@

print("* file %s: '%s' gets '0' as trace reason on line %s, use enum trace_reason instead (TRACE_REASON_UNKNOWN if the reason is not known)" % (p[0].file, tc, p[0].line))
cnt += 1


@finalize:python@
@@

if cnt > 0:
  print("""Use the following command to fix the above issues:
docker run --rm --user 1000 --workdir /workspace -v `pwd`:/workspace \\
    -e COCCINELLE_HOME=/usr/local/lib/coccinelle \\
    -it docker.io/cilium/coccicheck:2.4@sha256:24abe3fbb8e829fa41a68a3b76cb4df84fd5a87a7d1d6254c1c1fe5effb5bd1b \\
    spatch --include-headers --very-quiet --in-place bpf/ \\
    --sp-file contrib/coccinelle/zero_trace_reason.cocci\n
""")
