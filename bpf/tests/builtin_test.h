/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#include "lib/common.h"

static void __fill_rnd(void *buff, __u32 len)
{
	__u8 *dest = buff;
	__u32 i;

	for (i = 0; i < len; i++)
		dest[i] = random();
}

#define test___builtin_memzero_single(op, len)					\
	do {									\
		__u##op __x[len] __align_stack_8;				\
		__u##op __y[len] __align_stack_8;				\
		__bpf_memset_builtin(__y, 0, sizeof(__y));			\
		__fill_rnd(__x, sizeof(__x));					\
		__bpf_memzero(__x, sizeof(__x));				\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__builtin_memcmp(__x, __y, sizeof(__x)));		\
	} while (0)

static void test___builtin_memzero(void)
{
	/* ./builtin_gen memzero > builtin_memzero.h */
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
		__bpf_memcpy(__x, __y, sizeof(__x));				\
		barrier_data(__x);						\
		barrier_data(__y);						\
		barrier_data(__z);						\
		assert(!__builtin_memcmp(__x, __z, sizeof(__x)));		\
	} while (0)

static void test___builtin_memcpy(void)
{
	/* ./builtin_gen memcpy > builtin_memcpy.h */
	#include "builtin_memcpy.h"
}
