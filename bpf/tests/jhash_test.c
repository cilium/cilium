// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/xdp.h>
#include <lib/jhash.h>
#include "bpf/section.h"

CHECK("xdp", "jhash")
int bpf_test(__maybe_unused struct xdp_md *ctx)
{
	test_init();

	TEST("Non-zero", {
		unsigned int hash = jhash_3words(123, 234, 345, 456);

		if (hash != 2698615579)
			test_fatal("expected '2698615579' got '%lu'", hash);
	});

	TEST("Zero", {
		unsigned int hash = jhash_3words(0, 0, 0, 0);

		if (hash != 459859287)
			test_fatal("expected '459859287' got '%lu'", hash);
	});

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
