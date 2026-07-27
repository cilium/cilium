// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

#include "bpf_overlay.c"

CHECK("tc", "overlay_neigh_resolver")
int overlay_neigh_resolver(__maybe_unused struct __sk_buff *ctx)
{
	test_init();

	/* Due to https://lore.kernel.org/netdev/20251003073418.291171-1-daniel@iogearbox.net
	 * we shouldn't use bpf_redirect_neigh() from overlay programs without providing
	 * the next-hop.
	 */
	TEST("no_neigh_resolver_without_nh_on_overlay", {
		assert(!neigh_resolver_without_nh_available());
	});

	TEST("neigh_resolver_on_overlay", {
		assert(neigh_resolver_available());
	});

	test_finish();
}
