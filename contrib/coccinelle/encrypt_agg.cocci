// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium.
/// Prevent passing 0 as a value for monitor to send_trace_notify() when
/// flag is CLS_FLAG_{IPSEC,WIREGUARD}, because encrypted packets cannot be
/// aggregated due to a lack of connection tracking information.
// Confidence: Medium
// Comments:
// Options: --include-headers

@initialize:python@
@@

cnt = 0


@pass_monitor exists@
expression e1, e2, e3, e4, e5, e6, e7, e8;
identifier f;
expression m != 0;
position p;
@@

(
  send_trace_notify_flags@f(e1, e2, e3, e4, e5, e6, e7,
- m@p,
+ 0,
  CLS_FLAG_IPSEC);
|
  send_trace_notify_flags@f(e1, e2, e3, e4, e5, e6, e7,
- m@p,
+ 0,
  CLS_FLAG_WIREGUARD);
|
  \(send_trace_notify_flags4@f\|send_trace_notify_flags6@f\)(e1, e2, e3, e4, e5, e6, e7, e8,
- m@p,
+ 0,
  CLS_FLAG_IPSEC);
|
  \(send_trace_notify_flags4@f\|send_trace_notify_flags6@f\)(e1, e2, e3, e4, e5, e6, e7, e8,
- m@p,
+ 0,
  CLS_FLAG_WIREGUARD);
)

@script:python@
p << pass_monitor.p;
f << pass_monitor.f;
m << pass_monitor.m;
@@

print("* file %s: %s() has non-zero value as monitor argument for `CLS_FLAG_IPSEC/CLS_IPSEC_WIREGUARD` on line %s, zero instead" % (p[0].file, f, p[0].line))
cnt += 1


@declare_ctx exists@
identifier tc;
expression m != 0;
position p;
@@

(
  struct trace_ctx tc = {
-   .monitor = m@p,
+   .monitor = 0,
    .flags = CLS_FLAG_IPSEC,
    ...
  };
|
  struct trace_ctx tc = {
-   .monitor = m@p,
+   .monitor = 0,
    .flags = CLS_FLAG_WIREGUARD,
    ...
  };
|
  struct trace_ctx tc = ...;
  ... when != return ...;
- tc.monitor = m@p;
+ tc.monitor = 0;
  tc.flags = CLS_FLAG_IPSEC;
|
  struct trace_ctx tc = ...;
  ... when != return ...;
- tc.monitor = m@p;
+ tc.monitor = 0;
  tc.flags = CLS_FLAG_WIREGUARD;
|
  struct trace_ctx tc = ...;
  ... when != return ...;
- tc.monitor = m@p;
+ tc.monitor = 0;
  tc.flags |= CLS_FLAG_IPSEC;
|
  struct trace_ctx tc = ...;
  ... when != return ...;
- tc.monitor = m@p;
+ tc.monitor = 0;
  tc.flags |= CLS_FLAG_WIREGUARD;
|
  struct trace_ctx *tc;
  ... when != return ...;
- tc->monitor = m@p;
+ tc->monitor = 0;
  tc->flags = CLS_FLAG_IPSEC;
|
  struct trace_ctx *tc;
  ... when != return ...;
- tc->monitor = m@p;
+ tc->monitor = 0;
  tc->flags = CLS_FLAG_WIREGUARD;
|
  struct trace_ctx *tc;
  ... when != return ...;
- tc->monitor = m@p;
+ tc->monitor = 0;
  tc->flags |= CLS_FLAG_IPSEC;
|
  struct trace_ctx *tc;
  ... when != return ...;
- tc->monitor = m@p;
+ tc->monitor = 0;
  tc->flags |= CLS_FLAG_WIREGUARD;
)


@script:python@
p << declare_ctx.p;
tc << declare_ctx.tc;
m << declare_ctx.m;
@@

print("* file %s: '%s' gets 'CLS_FLAG_IPSEC/CLS_FLAG_WIREGUARD' as trace flags and '%s' as monitor on line %s, use zero for monitor instead" % (p[0].file, tc, m, p[0].line))
cnt += 1


@finalize:python@
@@

if cnt > 0:
  print("""Use the following command to fix the above issues:
docker run --rm --user 1000 --workdir /workspace -v `pwd`:/workspace \\
    -e COCCINELLE_HOME=/usr/local/lib/coccinelle \\
    -it docker.io/cilium/coccicheck:2.4@sha256:24abe3fbb8e829fa41a68a3b76cb4df84fd5a87a7d1d6254c1c1fe5effb5bd1b \\
    spatch --include-headers --very-quiet --in-place bpf/ \\
    --sp-file contrib/coccinelle/encrypt_agg.cocci\n
""")
