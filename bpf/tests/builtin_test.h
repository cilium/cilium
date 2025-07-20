/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "lib/common.h"

/* Manual slow versions, but doesn't matter for the sake of testing here.
 * Mainly to make sure we don't end up using the overridden builtin.
 */
static __always_inline __u32 __cmp_mem(const void *x, const void *y, __u32 len)
{
	const __u8 *x8 = x, *y8 = y;
	__u32 i;

	for (i = 0; i < len; i++) {
		if (x8[i] != y8[i])
			return 1;
	}

	return 0;
}

static __always_inline void __cpy_mem(void *d, void *s, __u32 len)
{
	__u8 *d8 = d, *s8 = s;
	__u32 i;

	for (i = 0; i < len; i++)
		d8[i] = s8[i];
}

static void __fill_rnd(void *buff, __u32 len)
{
	__u8 *dest = buff;
	__u32 i;

	for (i = 0; i < len; i++)
		dest[i] = (__u8)get_prandom_u32();
}

static __always_inline bool __corrupt_mem(void *d, __u32 len)
{
	bool corrupted = get_prandom_u32() & 1;
	__u32 pos = get_prandom_u32() % len;
	__u32 roundup_len;
	__u8 *d8 = d;

	/* When len is not a power of two, the verifier doesn't see boundaries
	 * of pos after the modulo operation. Apply an additional bitmask that
	 * doesn't change the value, but restricts len to the closest power of
	 * two.
	 */
	roundup_len = 1 << (32 - __builtin_clz(len - 1));
	asm volatile("%0 &= %1" : "+r"(pos) : "r"(roundup_len - 1));

	/* Compute d8 += pos in asm, because Clang optimizes it to a bitwise OR
	 * when it knows that d is aligned and len is 2, and the verifier
	 * forbids bitwise OR on pointers.
	 */
	asm volatile("%0 += %1" : "+r"(d8) : "r"(pos));

	if (corrupted)
		++*d8;
	return corrupted;
}

static void __fill_cnt(void *buff, __u32 len)
{
	__u8 *dest = buff;
	__u32 i;
	__u8 cnt = 0;

	for (i = 0; i < len; i++)
		dest[i] = cnt++;
}

#define ROUNDUP8(val) (((val) + 7) & ~7U)
#define ALIGN8_OFFSET(val) ((8 - (val) & 7) & 7)

#define test___builtin_memzero_single(len)					\
	do {									\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__bpf_memset_builtin(__y, 0, len);				\
		__fill_rnd(__x, len);						\
		barrier_data(__x);						\
		__bpf_memzero(__x, len);					\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, len));				\
	} while (0)

#define test___builtin_memcpy_single(len)					\
	do {									\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__u8 __z[len] __align_stack_8;					\
		__bpf_memset_builtin(__x, 0, len);				\
		__fill_rnd(__y, len);						\
		__bpf_memcpy_builtin(__z, __y, len);				\
		barrier_data(__x);						\
		barrier_data(__y);						\
		__bpf_memcpy(__x, __y, len);					\
		barrier_data(__x);						\
		barrier_data(__z);						\
		assert(!__cmp_mem(__x, __z, len));				\
	} while (0)

#define test___builtin_memcmp_single(len)					\
	do {									\
		bool res, cor;							\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__fill_rnd(__x, len);						\
		__cpy_mem(__y, __x, len);					\
		cor = __corrupt_mem(__y, len);					\
		barrier_data(__x);						\
		barrier_data(__y);						\
		res = __bpf_memcmp(__x, __y, len);				\
		assert(cor == res);						\
	} while (0)

/* Same as test___builtin_memcpy_single(). */
#define test___builtin_memmove1_single(len)					\
	do {									\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__u8 __z[len] __align_stack_8;					\
		__bpf_memset_builtin(__x, 0, len);				\
		__fill_rnd(__y, len);						\
		__bpf_memcpy_builtin(__z, __y, len);				\
		barrier_data(__x);						\
		barrier_data(__y);						\
		__bpf_memmove_bwd(__x, __y, len);				\
		barrier_data(__x);						\
		barrier_data(__z);						\
		assert(!__cmp_mem(__x, __z, len));				\
	} while (0)

/* Overlapping with src == dst. */
#define test___builtin_memmove2_single(len)					\
	do {									\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__u8 *__p_x = (__u8 *)__x;					\
		__u8 *__p_y = (__u8 *)__y;					\
		const __u32 off = 0;						\
		__fill_cnt(__x, len);						\
		__bpf_memcpy_builtin(__y, __x, len);				\
		__bpf_memcpy_builtin(__p_y + off, __x, len - off);		\
		barrier_data(__x);						\
		__bpf_memmove(__p_x + off, __x, len - off);			\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, len));				\
	} while (0)

/* Overlapping with src < dst. */
#define test___builtin_memmove3_single(len)					\
	do {									\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__u8 *__p_x = (__u8 *)__x;					\
		__u8 *__p_y = (__u8 *)__y;					\
		__u32 off = (len / 2) & ~1U;					\
		if (len >= 8)							\
			off &= ~7U;						\
		else if (len >= 4)						\
			off &= ~3U;						\
		__fill_cnt(__x, len);						\
		__bpf_memcpy_builtin(__y, __x, len);				\
		__bpf_memcpy_builtin(__p_y + off, __x, len - off);		\
		barrier_data(__x);						\
		__bpf_memmove(__p_x + off, __x, len - off);			\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, len));				\
	} while (0)

/* Overlapping with src > dst. */
#define test___builtin_memmove4_single(len)					\
	do {									\
		__u8 __xbuf[ROUNDUP8(len)] __align_stack_8;			\
		__u8 __ybuf[ROUNDUP8(len)] __align_stack_8;			\
		__u8 *__x = __xbuf + ALIGN8_OFFSET(len);			\
		__u8 *__y = __ybuf + ALIGN8_OFFSET(len);			\
		__u8 *__p_x = (__u8 *)__x;					\
		const __u32 off = (len / 2) & ~7U;				\
		__fill_cnt(__x, len);						\
		__bpf_memcpy_builtin(__y, __x, len);				\
		__bpf_memcpy_builtin(__y, __p_x + off, len - off);		\
		barrier_data(__x);						\
		__bpf_memmove(__x, __p_x + off, len - off);			\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, len));				\
	} while (0)

/* Same as test___builtin_memmove1_single(), but fwd. */
#define test___builtin_memmove5_single(len)					\
	do {									\
		__u8 __xbuf[ROUNDUP8(len)] __align_stack_8;			\
		__u8 __ybuf[ROUNDUP8(len)] __align_stack_8;			\
		__u8 __zbuf[ROUNDUP8(len)] __align_stack_8;			\
		__u8 *__x = __xbuf + ALIGN8_OFFSET(len);			\
		__u8 *__y = __ybuf + ALIGN8_OFFSET(len);			\
		__u8 *__z = __zbuf + ALIGN8_OFFSET(len);			\
		__bpf_memset_builtin(__x, 0, len);				\
		__fill_rnd(__y, len);						\
		__bpf_memcpy_builtin(__z, __y, len);				\
		barrier_data(__x);						\
		barrier_data(__y);						\
		__bpf_memmove_fwd(__x, __y, len);				\
		barrier_data(__x);						\
		barrier_data(__z);						\
		assert(!__cmp_mem(__x, __z, len));				\
	} while (0)
