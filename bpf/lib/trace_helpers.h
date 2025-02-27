/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef TRACE_ID_UTIL_H
#define TRACE_ID_UTIL_H

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>
#include "common.h"
#include "ip_options.h"

/* Define the ip trace ID map with __u64 trace_id */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32); /* only one key */
	__type(value, __u64); /* trace_id type */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} trace_id_map __section_maps_btf;

/* bpf_trace_id_set sets the trace_id in the map. */
static __always_inline __u64 bpf_trace_id_set(__u64 trace_id)
{
	__u32 __z = 0;
	__u64 *__cache = map_lookup_elem(&trace_id_map, &__z);

	if (__cache)
		*__cache = trace_id;

	return trace_id;
}

/* bpf_trace_id_get retrieves the trace_id from the map. */
static __always_inline __u64 bpf_trace_id_get(void)
{
	__u32 __z = 0;
	__u64 *__cache = map_lookup_elem(&trace_id_map, &__z);
	__u64 trace_id = 0;

	if (__cache)
		trace_id = *__cache;

	return trace_id;
}

/* Function to parse and store the trace_id if the feature is enabled. */
static __always_inline void
check_and_store_ip_trace_id(struct __ctx_buff *ctx)
{
	if (CONFIG(tracing_ip_option_type) == 0) {
		bpf_trace_id_set(0);
		return;
	}

	int ret;
	__s64 trace_id = 0;

	ret = trace_id_from_ctx(ctx, &trace_id, CONFIG(tracing_ip_option_type));
	if (IS_ERR(ret))
		bpf_trace_id_set(0);
	else
		bpf_trace_id_set(trace_id);
}

static __always_inline __u64 load_ip_trace_id(void)
{
	return bpf_trace_id_get();
}

#endif /* TRACE_ID_UTIL_H */
