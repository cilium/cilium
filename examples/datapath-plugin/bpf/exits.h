// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
} cilium_return SEC(".maps");

static __always_inline int
get_cilium_return()
{
	int zero = 0;
	int *ret;

	ret = (int *)bpf_map_lookup_elem(&cilium_return, &zero);
	if (!ret)
		return TC_ACT_SHOT;

	return *ret;
}

