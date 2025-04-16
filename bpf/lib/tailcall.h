/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#ifndef TAILCALL_H
#define TAILCALL_H

#include "common.h"
#include "config.h"
#include "ids.h"

#include "bpf/compiler.h"

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

#ifndef SKIP_CALLS_MAP
/* Private per-EP map for internal tail calls. Its bpffs pin is replaced every
 * time the BPF object is loaded. An existing pinned map is never reused.
 */
struct bpf_elf_map __section_maps cilium_calls = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_CALLS,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= CILIUM_PIN_REPLACE,
	.max_elem	= CILIUM_CALL_SIZE,
};
#endif /* SKIP_CALLS_MAP */

#ifndef SKIP_CALLS_MAP
static __always_inline __must_check int
tail_call_internal(struct __ctx_buff *ctx, const __u32 index, __s8 *ext_err)
{
	tail_call_static(ctx, cilium_calls, index);

	if (ext_err)
		*ext_err = (__s8)index;
	return DROP_MISSED_TAIL_CALL;
}
#endif /* SKIP_CALLS_MAP */

/* invoke_tailcall_if() is a helper which based on COND either selects to emit
 * a tail call for the underlying function when true or emits it as inlined
 * when false. COND can be selected by one or multiple compile time flags.
 *
 * [...]
 * invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
 *                    CILIUM_CALL_FOO, foo_fn);
 * [...]
 *
 * The loader will only load tail calls if they are invoked at least once.
 */

#define __invoke_tailcall_if_0(NAME, FUNC, EXT_ERR)			\
	FUNC(ctx)
#define __invoke_tailcall_if_1(NAME, FUNC, EXT_ERR)			\
	({								\
		tail_call_internal(ctx, NAME, EXT_ERR);			\
	})
#define invoke_tailcall_if(COND, NAME, FUNC, EXT_ERR)			\
	__eval(__invoke_tailcall_if_, COND)(NAME, FUNC, EXT_ERR)

#define __invoke_traced_tailcall_if_0(NAME, FUNC, TRACE, EXT_ERR)	\
	FUNC(ctx, TRACE, EXT_ERR)
#define __invoke_traced_tailcall_if_1(NAME, FUNC, TRACE, EXT_ERR)	\
	({								\
		tail_call_internal(ctx, NAME, EXT_ERR);			\
	})
#define invoke_traced_tailcall_if(COND, NAME, FUNC, TRACE, EXT_ERR)	\
	__eval(__invoke_traced_tailcall_if_, COND)(NAME, FUNC, TRACE,	\
						   EXT_ERR)

#endif /* TAILCALL_H */
