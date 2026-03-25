#pragma once

#include "common.h"

#ifndef TRACE_EXTENSION
#define TRACE_EXTENSION
#define trace_extension_hook(ctx, msg) do {} while (0)
#endif

struct trace_notify {
	NOTIFY_CAPTURE_HDR
	__u32		src_label;
	__u32		dst_label;
	__u16		dst_id;
	__u8		reason;
	__u8		flags; /* __u8 instead of cls_flags_t so that it will error
				* when cls_flags_t grows (move to flags_lower/flags_upper).
				*/
	__u32		ifindex;
	union {
		union v4addr	orig_ip4;
		union v6addr	orig_ip6;
	};
	__u64		ip_trace_id;
	TRACE_EXTENSION
} __align_stack_8;
