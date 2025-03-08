/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "ipv6.h"
#include "ids.h"

#include "bpf/compiler.h"

/* Global map to jump into policy enforcement of sending endpoint */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_PROG_MAP_SIZE);
} cilium_egresscall_policy __section_maps_btf;

static __always_inline __must_check int
tail_call_egress_policy(struct __ctx_buff *ctx, __u16 endpoint_id)
{
	tail_call_dynamic(ctx, &cilium_egresscall_policy, endpoint_id);
	/* same issue as for the cilium_call_policy calls */
	return DROP_EP_NOT_READY;
}

#ifndef SKIP_CALLS_MAP
/* Private per-EP map for internal tail calls. Its bpffs pin is replaced every
 * time the BPF object is loaded. An existing pinned map is never reused.
 */
struct bpf_elf_map __section_maps cilium_calls = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_CALLS,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.pinning	= CILIUM_PIN_REPLACE,
	.max_elem	= CILIUM_CALL_SIZE,
};
#endif /* SKIP_CALLS_MAP */

#ifndef SKIP_CALLS_MAP
static __always_inline __must_check int
tail_call_internal(struct __ctx_buff *ctx, const __u32 index, __s8 *ext_err)
{
	tail_call_static(ctx, cilium_calls, index);

	if (ext_err)
		*ext_err = (__s8)index;
	return DROP_MISSED_TAIL_CALL;
}
#endif /* SKIP_CALLS_MAP */
