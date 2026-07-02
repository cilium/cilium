// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Tests allow_vlan() when slot0=0 (allow all VLANs). */

#include <bpf/ctx/skb.h>
#include "common.h"

#include <lib/vlan.h>

ASSIGN_CONFIG(__u16, vlan_filter_id_0, 0)
ASSIGN_CONFIG(__u16, vlan_filter_id_1, 0xFFFF)
ASSIGN_CONFIG(__u16, vlan_filter_id_2, 0xFFFF)
ASSIGN_CONFIG(__u16, vlan_filter_id_3, 0xFFFF)
ASSIGN_CONFIG(__u16, vlan_filter_id_4, 0xFFFF)

CHECK("tc", "vlan_filter_allow_all")
int bpf_test(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	TEST("allow_all", {
		assert(allow_vlan(0, 1));
		assert(allow_vlan(0, 100));
		assert(allow_vlan(0, 4094));
	});

	test_finish();
}
