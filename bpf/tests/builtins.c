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

	/* ./builtin_gen memzero 128 > builtin_memzero.h */
	#include "builtin_memzero.h"

	test_finish();
}

CHECK("tc", "builtin_memcpy")
int test_builtin_memcpy(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* ./builtin_gen memcpy 128 > builtin_memcpy.h */
	#include "builtin_memcpy.h"

	test_finish();
}

CHECK("tc", "builtin_memcmp")
int test_builtin_memcmp(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	int i;

	for (i = 0; i < BUILTIN_MEMCMP_RUNS; ++i) {
		/* ./builtin_gen memcmp 128 > builtin_memcmp.h */
		#include "builtin_memcmp.h"
	}

	test_finish();
}

/**
 * Note the test is intentionally split in I and II due to a CLANG
 * bug (possibly out of jump labels), see commit history and
 * PR#41017 for more details.
 */
CHECK("tc", "builtin_memmove")
int test_builtin_memmove(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* ./builtin_gen memmove1 128  > builtin_memmove.h */
	/* ./builtin_gen memmove2 128 >> builtin_memmove.h */
	/* ./builtin_gen memmove3 128 >> builtin_memmove.h */
	#include "builtin_memmove.h"

	test_finish();
}

CHECK("tc", "builtin_memmove2")
int test_builtin_memmove2(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* ./builtin_gen memmove4 128 > builtin_memmove2.h */
	/* ./builtin_gen memmove5 128 >> builtin_memmove2.h */
	#include "builtin_memmove2.h"

	test_finish();
}
