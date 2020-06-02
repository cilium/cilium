// SPDX-License-Identifier: GPL-2.0
/// Find tail calls not followed by a call to send_drop_notify_error with
/// DROP_MISSED_TAIL_CALL. Such code patterns may lead to missed tail calls not
/// being logged.
// Confidence: Medium
// Copyright (C) 2020 Authors of Cilium.
// Comments:
// Options: --include-headers

@initialize:python@
@@

cnt = 0

// We whitelist two ep_tail_call cases:
// - One used in invoke_tailcall_if as we'll check invoke_tailcall_if itself.
// - One used in send_drop_notify() as we're already in the code that's
//   supposed to be called after tail calls.
def whitelist_tailcalls(p):
    return p.current_element != "send_drop_notify" and \
           not p.file.endswith("lib/tailcall.h")


@rule@
position p : script:python() { whitelist_tailcalls(p[0]) };
expression e1, e2, e3, e4, x;
symbol ret;
@@

(
  // Classic cases of send_drop_notify_error with DROP_MISSED_TAIL_CALL.
  ep_tail_call(...);
  ... when forall
  return send_drop_notify_error(e1, e2, DROP_MISSED_TAIL_CALL, ...);
|
  ep_tail_call(...);
  <+... when forall
  x = DROP_MISSED_TAIL_CALL;
  ...+>
  return send_drop_notify_error(e1, e2, x, ...);
|
  // We also whitelist any function returning DROP_MISSED_TAIL_CALL, assuming
  // this will be catch afterwards and transformed in call to
  // send_drop_notify_error().
  ep_tail_call(...);
  ... when forall
  return DROP_MISSED_TAIL_CALL;
|
  ep_tail_call(...);
  <+... when forall
  x = DROP_MISSED_TAIL_CALL;
  ...+>
  return x;
|
  ep_tail_call@p(...);
|
  // invoke_tailcall_if sets variable ret which should be used in subsequent
  // call to send_drop_notify{,_error}.
  invoke_tailcall_if(...);
  ... when != ret = ...;
      when forall
  \(
    return send_drop_notify(e1, e2, e3, e4, ret, CTX_ACT_DROP, ...);
  \|
    return send_drop_notify_error(e1, e2, ret, CTX_ACT_DROP, ...);
  \)
|
  invoke_tailcall_if(...);
  ... when != ret = ...;
      when forall
  if (IS_ERR(ret))
    \(
      return send_drop_notify(e1, e2, e3, e4, ret, CTX_ACT_DROP, ...);
    \|
      return send_drop_notify_error(e1, e2, ret, CTX_ACT_DROP, ...);
    \)
|
  invoke_tailcall_if@p(...);
)


@script:python@
p << rule.p;
@@

print "* file %s: DROP_MISSED_TAIL_CALL missing after tail call on line %s" % (p[0].file, p[0].line)
cnt += 1


@finalize:python@
@@

if cnt > 0:
  print """Unlogged tail calls found. Please fix and use the following command to check:
docker run --rm --user 1000 --workdir /workspace -v `pwd`:/workspace \\
    -it docker.io/cilium/coccicheck make -C bpf coccicheck\n
"""
