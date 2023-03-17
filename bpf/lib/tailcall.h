/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#ifndef TAILCALL_H
#define TAILCALL_H

#include "config.h"

#define __eval(x, ...) x ## __VA_ARGS__

#define __and_00 0
#define __and_01 0
#define __and_10 0
#define __and_11 1
#define __and_0(y)  __eval(__and_0, y)
#define __and_1(y)  __eval(__and_1, y)
#define __and(x, y) __eval(__and_, x)(y)

#define __or_00 0
#define __or_01 1
#define __or_10 1
#define __or_11 1
#define __or_0(y)  __eval(__or_0, y)
#define __or_1(y)  __eval(__or_1, y)
#define __or(x, y) __eval(__or_, x)(y)

#define __or3_1(y, z)  1
#define __or3_0(y, z)  __or(y, z)
#define __or3(x, y, z) __eval(__or3_, x)(y, z)

#define __or4_1(x, y, z) 1
#define __or4_0(x, y, z) __eval(__or3_, x)(y, z)
#define __or4(w, x, y, z) __eval(__or4_, w)(x, y, z)

#define __not_0 1
#define __not_1 0
#define __not(x) __eval(__not_, x)

/* declare_tailcall_if() and invoke_tailcall_if() is a pair
 * of helpers which based on COND either selects to emit a
 * tail call for the underlying function when true or emits
 * it as inlined when false. COND can be selected by one or
 * multiple compile time flags.
 *
 * Usage example:
 *
 * 1) Declaration:
 *
 * declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
 *                     CILIUM_CALL_FOO)
 * int foo_fn(struct __ctx_buff *ctx)
 * {
 *    [...]
 * }
 *
 * 2) Call-site:
 *
 * [...]
 * invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
 *                    CILIUM_CALL_FOO, foo_fn);
 * [...]
 *
 * 3) Compilation result:
 *
 * When compiled with -DENABLE_IPV4 and -DENABLE_IPV6 both
 * set, then above emits a tail call as follows:
 *
 * __attribute__((section("2" "/" "10"), used))
 * int foo_fn(struct __ctx_buff *ctx)
 * {
 *    [...]
 * }
 *
 * [...]
 * do { ep_tail_call(ctx, 10); ret = -140; } while (0);
 * [...]
 *
 * The fall-through side sets DROP_MISSED_TAIL_CALL as ret.
 *
 * When only one of them is set in the above example or none
 * of them, then the code emission looks like:
 *
 * static __inline __attribute__ ((__always_inline__))
 * int foo_fn(struct __ctx_buff *ctx)
 * {
 *    [...]
 * }
 *
 * [...]
 * return foo_fn(ctx);
 * [...]
 *
 * Selectors can be single is_defined(), or multiple ones
 * combined with __and() or __or() macros. COND must be
 * the same expression for declare_tailcall_if() and the
 * invoke_tailcall_if() part.
 */
#define __declare_tailcall_if_0(NAME)         \
	static __always_inline
#define __declare_tailcall_if_1(NAME)         \
	__section_tail(CILIUM_MAP_CALLS, NAME)
#define declare_tailcall_if(COND, NAME)       \
	__eval(__declare_tailcall_if_, COND)(NAME)

#define __invoke_tailcall_if_0(NAME, FUNC)    \
	return FUNC(ctx)
#define __invoke_tailcall_if_1(NAME, FUNC)    \
	do {                                  \
		ep_tail_call(ctx, NAME);      \
		ret = DROP_MISSED_TAIL_CALL;  \
	} while (0)
#define invoke_tailcall_if(COND, NAME, FUNC)  \
	__eval(__invoke_tailcall_if_, COND)(NAME, FUNC)

#endif /* TAILCALL_H */
