// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include <node_config.h>

#include "builtin_test.h"

CHECK("tc", "builtin_memzero")
int test_builtin_memzero(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* ./builtin_gen memzero 96 > builtin_memzero.h */
	#include "builtin_memzero.h"

	test_finish();
}

CHECK("tc", "builtin_memcpy")
int test_builtin_memcpy(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* ./builtin_gen memcpy 96 > builtin_memcpy.h */
	#include "builtin_memcpy.h"

	test_finish();
}

CHECK("tc", "builtin_memcmp")
int test_builtin_memcmp(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	int i;

	for (i = 0; i < 70; i++) {
		/* ./builtin_gen memcmp 32 > builtin_memcmp.h */
		#include "builtin_memcmp.h"
	}

	test_finish();
}

CHECK("tc", "builtin_memcmp_large")
int test_builtin_memcmp_large(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* ./builtin_gen memcmp 72 > builtin_memcmp_large.h */
	#include "builtin_memcmp_large.h"

	test_finish();
}

CHECK("tc", "builtin_memmove")
int test_builtin_memmove(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* ./builtin_gen memmove1 96  > builtin_memmove.h */
	/* ./builtin_gen memmove2 96 >> builtin_memmove.h */
	/* ./builtin_gen memmove3 96 >> builtin_memmove.h */
	/* ./builtin_gen memmove4 96 >> builtin_memmove.h */
	/* ./builtin_gen memmove5 96 >> builtin_memmove.h */
	#include "builtin_memmove.h"

	test_finish();
}
