// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/ctx/skb.h>
#include <bpf/helpers.h>
#include <bpf/loader.h>
#include <bpf/section.h>

#include "drop_reasons.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
} cilium_return __section_maps_btf;

static __always_inline int
get_cilium_return()
{
	int zero = 0;
	int *ret;

	ret = map_lookup_elem(&cilium_return, &zero);
	if (!ret)
		return DROP_INVALID_RETURN;

	return *ret;
}

static __always_inline int
defer_cilium_return(int ret)
{
	int zero = 0;

	if (map_update_elem(&cilium_return, &zero, &ret, 0))
		return DROP_INVALID_RETURN;

	return TC_ACT_UNSPEC;
}

#define EXIT_HANDLER()                   \
__section_exit                           \
int exit_handler(int ret)                \
{                                        \
	return defer_cilium_return(ret); \
}
