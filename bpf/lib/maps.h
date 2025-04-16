/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "ids.h"

#include "bpf/compiler.h"

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
