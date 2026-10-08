/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

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
} cilium_percpu_trace_id __section_maps_btf;

/* bpf_trace_id_set sets the trace_id in the map. */
static __always_inline void bpf_trace_id_set(__u64 trace_id)
{
	__u32 zero = 0;
	__u64 *value = map_lookup_elem(&cilium_percpu_trace_id, &zero);

	if (value)
		*value = trace_id;
}

/* bpf_trace_id_get retrieves the trace_id from the map. */
static __always_inline __u64 bpf_trace_id_get(void)
{
	__u32 zero = 0;
	__u64 *value = map_lookup_elem(&cilium_percpu_trace_id, &zero);

	if (value)
		return *value;
	return 0;
}

/* Function to parse and store the trace_id if the feature is enabled. */
static __always_inline void
check_and_store_ip_trace_id(struct __ctx_buff *ctx)
{
	__s64 trace_id = 0;
	int ret;

	if (CONFIG(tracing_ip_option_type) == 0)
		return;

	ret = trace_id_from_ctx(ctx, &trace_id, CONFIG(tracing_ip_option_type));
	if (IS_ERR(ret))
		bpf_trace_id_set(0);
	else
		bpf_trace_id_set(trace_id);
}

static __always_inline __u64 load_ip_trace_id(void)
{
	if (CONFIG(tracing_ip_option_type) == 0)
		return 0;
	return bpf_trace_id_get();
}
