/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>
#include "common.h"
#include "ip_options.h"
#include "trace_id.h"

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
