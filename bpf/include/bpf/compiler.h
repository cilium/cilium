/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BPF_COMPILER_H_
#define __BPF_COMPILER_H_

#ifndef __non_bpf_context
# include "stddef.h"
#endif

#ifndef __section
# define __section(X)		__attribute__((section(X), used))
#endif

#ifndef __maybe_unused
# define __maybe_unused		__attribute__((__unused__))
#endif

#ifndef offsetof
# define offsetof(T, M)		__builtin_offsetof(T, M)
#endif

#ifndef field_sizeof
# define field_sizeof(T, M)	sizeof((((T *)NULL)->M))
#endif

#ifndef __packed
# define __packed		__attribute__((packed))
#endif

#ifndef likely
# define likely(X)		__builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
# define unlikely(X)		__builtin_expect(!!(X), 0)
#endif

#undef __always_inline		/* stddef.h defines its own */
#define __always_inline		inline __attribute__((always_inline))

#ifndef __stringify
# define __stringify(X)		#X
#endif

#ifndef __fetch
# define __fetch(X)		(__u32)(__u64)(&(X))
#endif

#ifndef build_bug_on
# define build_bug_on(E)	((void)sizeof(char[1 - 2*!!(E)]))
#endif

#ifndef __printf
# define __printf(X, Y)		__attribute__((__format__(printf, X, Y)))
#endif

static __always_inline void bpf_barrier(void)
{
	/* Workaround to avoid verifier complaint:
	 * "dereference of modified ctx ptr R5 off=48+0, ctx+const is allowed, ctx+const+const is not"
	 */
	asm volatile("" ::: "memory");
}

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(A)		(sizeof(A) / sizeof((A)[0]))
#endif

#ifndef __READ_ONCE
# define __READ_ONCE(X)		(*(volatile typeof(X) *)&X)
#endif

#ifndef __WRITE_ONCE
# define __WRITE_ONCE(X, V)	(*(volatile typeof(X) *)&X) = (V)
#endif

/* {READ,WRITE}_ONCE() with verifier workaround via bpf_barrier(). */

#ifndef READ_ONCE
# define READ_ONCE(X)						\
				({ typeof(X) __val;		\
				   __val = __READ_ONCE(X);	\
				   bpf_barrier();		\
				   __val; })
#endif

#ifndef WRITE_ONCE
# define WRITE_ONCE(X, V)       				\
				({ typeof(X) __val = (V);	\
				   __WRITE_ONCE(X, __val);	\
				   bpf_barrier();		\
				   __val; })
#endif

#endif /* __BPF_COMPILER_H_ */
