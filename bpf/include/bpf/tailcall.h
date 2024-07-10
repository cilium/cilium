/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "compiler.h"

#if defined(__bpf__)

/* Don't gamble, but _guarantee_ that LLVM won't optimize setting
 * r2 and r3 from different paths ending up at the same call insn as
 * otherwise we won't be able to use the jmpq/nopl retpoline-free
 * patching by the x86-64 JIT in the kernel.
 *
 * Note on clobber list: we need to stay in-line with BPF calling
 * convention, so even if we don't end up using r0, r4, r5, we need
 * to mark them as clobber so that LLVM doesn't end up using them
 * before / after the call.
 *
 * WARNING: The loader relies on the exact instruction sequence
 * emitted by this macro. Consult with the loader team before
 * changing this macro.
 */
#define tail_call_static(ctx_ptr, map, slot)				\
{								\
	if (!__builtin_constant_p(slot))			\
		__throw_build_bug();				\
								\
	asm volatile("r1 = %[ctx]\n\t"				\
		"r2 = " __stringify(map) " ll\n\t"		\
		"r3 = %[slot_idx]\n\t"				\
		"call 12\n\t"					\
		:: [ctx]"r"(ctx_ptr), [slot_idx]"i"(slot)	\
		: "r0", "r1", "r2", "r3", "r4", "r5");		\
}

static __always_inline __maybe_unused void
tail_call_dynamic(struct __ctx_buff *ctx, const void *map, __u32 slot)
{
	if (__builtin_constant_p(slot))
		__throw_build_bug();

	/* Only for the case where slot is not known at compilation time,
	 * we give LLVM a free pass to optimize since we cannot do much
	 * here anyway as x86-64 JIT will emit a retpoline for this case.
	 */
	tail_call(ctx, map, slot);
}
#else
/* BPF unit tests compile some BPF code under their native arch. Tail calls
 * won't work in this context. Only compile above under __bpf__ target.
 */
# define tail_call_static(ctx, map, slot)	__throw_build_bug()
# define tail_call_dynamic(ctx, map, slot)	__throw_build_bug()
#endif /* __bpf__ */
