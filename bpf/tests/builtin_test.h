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
		dest[i] = random();
}

static __always_inline bool __corrupt_mem(void *d, __u32 len)
{
	bool corrupted = random() % 2 == 1;
	__u32 pos = random() % len;
	__u8 *d8 = d;

	if (corrupted)
		d8[pos]++;
	return corrupted;
}

static void __fill_cnt(void *buff, __u32 len)
{
	__u8 *dest = buff;
	__u32 i, cnt = 0;

	for (i = 0; i < len; i++)
		dest[i] = cnt++;
}

#define test___builtin_memzero_single(op, len)					\
	do {									\
		__u##op __x[len] __align_stack_8;				\
		__u##op __y[len] __align_stack_8;				\
		__bpf_memset_builtin(__y, 0, sizeof(__y));			\
		__fill_rnd(__x, sizeof(__x));					\
		barrier_data(__x);						\
		__bpf_memzero(__x, sizeof(__x));				\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, sizeof(__x)));			\
	} while (0)

static void test___builtin_memzero(void)
{
	/* ./builtin_gen memzero 768 > builtin_memzero.h */
	#include "builtin_memzero.h"
}

#define test___builtin_memcpy_single(op, len)					\
	do {									\
		__u##op __x[len] __align_stack_8;				\
		__u##op __y[len] __align_stack_8;				\
		__u##op __z[len] __align_stack_8;				\
		__bpf_memset_builtin(__x, 0, sizeof(__x));			\
		__fill_rnd(__y, sizeof(__y));					\
		__bpf_memcpy_builtin(__z, __y, sizeof(__z));			\
		barrier_data(__x);						\
		barrier_data(__y);						\
		__bpf_memcpy(__x, __y, sizeof(__x));				\
		barrier_data(__x);						\
		barrier_data(__z);						\
		assert(!__cmp_mem(__x, __z, sizeof(__x)));			\
	} while (0)

static void test___builtin_memcpy(void)
{
	/* ./builtin_gen memcpy 768 > builtin_memcpy.h */
	#include "builtin_memcpy.h"
}

#define test___builtin_memcmp_single(op, len)					\
	do {									\
		bool res, cor;							\
		__u##op __x[len] __align_stack_8;				\
		__u##op __y[len] __align_stack_8;				\
		__fill_rnd(__x, sizeof(__x));					\
		__cpy_mem(__y, __x, sizeof(__x));				\
		cor = __corrupt_mem(__y, sizeof(__x));				\
		barrier_data(__x);						\
		barrier_data(__y);						\
		res = __bpf_memcmp(__x, __y, sizeof(__x));			\
		assert(cor == res);						\
	} while (0)

static void test___builtin_memcmp(void)
{
	int i;

	for (i = 0; i < 100; i++) {
		/* ./builtin_gen memcmp 256 > builtin_memcmp.h */
		#include "builtin_memcmp.h"
	}
}

/* Same as test___builtin_memcpy_single(). */
#define test___builtin_memmove1_single(op, len)					\
	do {									\
		__u##op __x[len] __align_stack_8;				\
		__u##op __y[len] __align_stack_8;				\
		__u##op __z[len] __align_stack_8;				\
		__bpf_memset_builtin(__x, 0, sizeof(__x));			\
		__fill_rnd(__y, sizeof(__y));					\
		__bpf_memcpy_builtin(__z, __y, sizeof(__z));			\
		barrier_data(__x);						\
		barrier_data(__y);						\
		__bpf_memmove(__x, __y, sizeof(__x));				\
		barrier_data(__x);						\
		barrier_data(__z);						\
		assert(!__cmp_mem(__x, __z, sizeof(__x)));			\
	} while (0)

/* Overlapping with src == dst. */
#define test___builtin_memmove2_single(op, len)					\
	do {									\
		__u##op __x[len] __align_stack_8;				\
		__u##op __y[len] __align_stack_8;				\
		__u8 *__p_x = (__u8 *)__x;					\
		__u8 *__p_y = (__u8 *)__y;					\
		const __u32 off = 0;						\
		__fill_cnt(__x, sizeof(__x));					\
		__bpf_memcpy_builtin(__y, __x, sizeof(__x));			\
		__bpf_memcpy_builtin(__p_y + off, __x, sizeof(__x) - off);	\
		barrier_data(__x);						\
		__bpf_memmove(__p_x + off, __x, sizeof(__x) - off);		\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, sizeof(__x)));			\
	} while (0)

/* Overlapping with src < dst. */
#define test___builtin_memmove3_single(op, len)					\
	do {									\
		__u##op __x[len] __align_stack_8;				\
		__u##op __y[len] __align_stack_8;				\
		__u8 *__p_x = (__u8 *)__x;					\
		__u8 *__p_y = (__u8 *)__y;					\
		const __u32 off = (sizeof(__x[0]) * len / 2) & ~1U;		\
		__fill_cnt(__x, sizeof(__x));					\
		__bpf_memcpy_builtin(__y, __x, sizeof(__x));			\
		__bpf_memcpy_builtin(__p_y + off, __x, sizeof(__x) - off);	\
		barrier_data(__x);						\
		__bpf_memmove(__p_x + off, __x, sizeof(__x) - off);		\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, sizeof(__x)));			\
	} while (0)

/* Overlapping with src > dst. */
#define test___builtin_memmove4_single(op, len)					\
	do {									\
		__u##op __x[len] __align_stack_8;				\
		__u##op __y[len] __align_stack_8;				\
		__u8 *__p_x = (__u8 *)__x;					\
		const __u32 off = (sizeof(__x[0]) * len / 2) & ~1U;		\
		__fill_cnt(__x, sizeof(__x));					\
		__bpf_memcpy_builtin(__y, __x, sizeof(__x));			\
		__bpf_memcpy_builtin(__y, __p_x + off, sizeof(__x) - off);	\
		barrier_data(__x);						\
		__bpf_memmove(__x, __p_x + off, sizeof(__x) - off);		\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, sizeof(__x)));			\
	} while (0)

static void test___builtin_memmove(void)
{
	/* ./builtin_gen memmove1 768  > builtin_memmove.h */
	/* ./builtin_gen memmove2 768 >> builtin_memmove.h */
	/* ./builtin_gen memmove3 768 >> builtin_memmove.h */
	/* ./builtin_gen memmove4 768 >> builtin_memmove.h */
	#include "builtin_memmove.h"
}
