// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Tests allow_vlan() with slot0=100, slot1=200, slots2-4=unused. */

#include <bpf/ctx/skb.h>
#include "common.h"

#include <lib/vlan.h>

ASSIGN_CONFIG(__u16, vlan_filter_id_0, 100)
ASSIGN_CONFIG(__u16, vlan_filter_id_1, 200)
ASSIGN_CONFIG(__u16, vlan_filter_id_2, 0xFFFF)
ASSIGN_CONFIG(__u16, vlan_filter_id_3, 0xFFFF)
ASSIGN_CONFIG(__u16, vlan_filter_id_4, 0xFFFF)

CHECK("tc", "vlan_filter")
int bpf_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	TEST("slot0_match", {
		assert(allow_vlan(0, 100));
	});

	TEST("slot1_match", {
		assert(allow_vlan(0, 200));
	});

	TEST("sentinel_deny", {
		assert(!allow_vlan(0, 300));
	});

	TEST("no_partial_match", {
		assert(!allow_vlan(0, 101));
	});

	TEST("ifindex_ignored", {
		assert(allow_vlan(99, 100));
		assert(!allow_vlan(99, 300));
	});

	test_finish();
}
