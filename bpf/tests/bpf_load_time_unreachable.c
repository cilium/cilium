// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include <lib/static_data.h>
#include <bpf/assert.h>

DECLARE_CONFIG(bool, example_setting, "Example setting for load time unreachable test")
ASSIGN_CONFIG(bool, example_setting, true)

CHECK(PROG_TYPE, "load_time_unreachable")
int test_load_time_unreachable()
{
	test_init();

	if (!CONFIG(example_setting))
		load_time_unreachable();
	return 0;

	test_finish();
}
