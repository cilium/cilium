/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_DBG__
#define __LIB_DBG__

/* Trace types */
enum {
	DBG_UNSPEC,
	DBG_GENERIC, /* Generic, no message, useful to dump random integers */
	DBG_LOCAL_DELIVERY,
	DBG_ENCAP,
	DBG_LXC_FOUND,
	DBG_POLICY_DENIED,
	DBG_CT_LOOKUP,		/* unused */
	DBG_CT_LOOKUP_REV,	/* unused */
	DBG_CT_MATCH,
	DBG_CT_CREATED,		/* unused */
	DBG_CT_CREATED2,	/* unused */
	DBG_ICMP6_HANDLE,
	DBG_ICMP6_REQUEST,
	DBG_ICMP6_NS,
	DBG_ICMP6_TIME_EXCEEDED,
	DBG_CT_VERDICT,
	DBG_DECAP,
	DBG_PORT_MAP,
	DBG_ERROR_RET,
	DBG_TO_HOST,
	DBG_TO_STACK,
	DBG_PKT_HASH,
	DBG_LB6_LOOKUP_MASTER,
	DBG_LB6_LOOKUP_MASTER_FAIL,
	DBG_LB6_LOOKUP_SLAVE,
	DBG_LB6_LOOKUP_SLAVE_SUCCESS,
	DBG_LB6_LOOKUP_SLAVE_V2_FAIL,
	DBG_LB6_LOOKUP_BACKEND_FAIL,
	DBG_LB6_REVERSE_NAT_LOOKUP,
	DBG_LB6_REVERSE_NAT,
	DBG_LB4_LOOKUP_MASTER,
	DBG_LB4_LOOKUP_MASTER_FAIL,
	DBG_LB4_LOOKUP_SLAVE,
	DBG_LB4_LOOKUP_SLAVE_SUCCESS,
	DBG_LB4_LOOKUP_SLAVE_V2_FAIL,
	DBG_LB4_LOOKUP_BACKEND_FAIL,
	DBG_LB4_REVERSE_NAT_LOOKUP,
	DBG_LB4_REVERSE_NAT,
	DBG_LB4_LOOPBACK_SNAT,
	DBG_LB4_LOOPBACK_SNAT_REV,
	DBG_CT_LOOKUP4,
	DBG_RR_SLAVE_SEL,
	DBG_REV_PROXY_LOOKUP,
	DBG_REV_PROXY_FOUND,
	DBG_REV_PROXY_UPDATE,
	DBG_L4_POLICY,
	DBG_NETDEV_IN_CLUSTER, /* arg1: security-context, arg2: unused */
	DBG_NETDEV_ENCAP4, /* arg1 encap lookup key, arg2: identity */
	DBG_CT_LOOKUP4_1,       /* arg1: saddr
				 * arg2: daddr
				 * arg3: (sport << 16) | dport
				 */
	DBG_CT_LOOKUP4_2,       /* arg1: (nexthdr << 8) | flags
				 * arg2: direction
				 * arg3: unused
				 */
	DBG_CT_CREATED4,        /* arg1: (unused << 16) | rev_nat_index
				 * arg2: src sec-id
				 * arg3: lb address
				 */ 
	DBG_CT_LOOKUP6_1,       /* arg1: saddr (last 4 bytes)
				 * arg2: daddr (last 4 bytes)
				 * arg3: (sport << 16) | dport
				 */
	DBG_CT_LOOKUP6_2,       /* arg1: (nexthdr << 8) | flags
				 * arg2: direction
				 * arg3: unused
				 */
	DBG_CT_CREATED6,        /* arg1: (unused << 16) | rev_nat_index
				 * arg2: src sec-id
				 * arg3: unused
				 */
	DBG_SKIP_PROXY,          /* arg1: ctx->tc_index
				  * arg2: unused
				  */
	DBG_L4_CREATE,		/* arg1: src sec-id
				 * arg2: dst sec-id
				 * arg3: (dport << 16) | protocol
				 */
	DBG_IP_ID_MAP_FAILED4,	/* arg1: daddr
				 * arg2: unused
				 * arg3: unused */
	DBG_IP_ID_MAP_FAILED6,	/* arg1: daddr (last 4 bytes)
				 * arg2: unused
				 * arg3: unused */
	DBG_IP_ID_MAP_SUCCEED4,	/* arg1: daddr
				 * arg2: identity
				 * arg3: unused */
	DBG_IP_ID_MAP_SUCCEED6,	/* arg1: daddr (last 4 bytes)
				 * arg2: identity
				 * arg3: unused */
	DBG_LB_STALE_CT,	/* arg1: svc rev_nat_id
				   arg2: stale CT rev_nat_id
				   arg3: unused */
	DBG_INHERIT_IDENTITY	/* arg1: ctx->mark
				 * arg2: unused */
};

/* Capture types */
enum {
	DBG_CAPTURE_UNSPEC,
	DBG_CAPTURE_FROM_RESERVED1,
	DBG_CAPTURE_FROM_RESERVED2,
	DBG_CAPTURE_FROM_RESERVED3,
	DBG_CAPTURE_DELIVERY,
	DBG_CAPTURE_FROM_LB,
	DBG_CAPTURE_AFTER_V46,
	DBG_CAPTURE_AFTER_V64,
	DBG_CAPTURE_PROXY_PRE,
	DBG_CAPTURE_PROXY_POST,
	DBG_CAPTURE_SNAT_PRE,
	DBG_CAPTURE_SNAT_POST,
};

#ifndef EVENT_SOURCE
#define EVENT_SOURCE 0
#endif

#ifdef DEBUG
#include "events.h"
#endif

#ifdef DEBUG
#include "common.h"
#include "utils.h"

# define printk(fmt, ...)					\
		({						\
			char ____fmt[] = fmt;			\
			trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);		\
		})

struct debug_msg {
	NOTIFY_COMMON_HDR
	__u32		arg1;
	__u32		arg2;
	__u32		arg3;
};

static __always_inline void cilium_dbg(struct __ctx_buff *ctx, __u8 type,
				       __u32 arg1, __u32 arg2)
{
	struct debug_msg msg = {
		__notify_common_hdr(CILIUM_NOTIFY_DBG_MSG, type),
		.arg1	= arg1,
		.arg2	= arg2,
	};

	ctx_event_output(ctx, &EVENTS_MAP, BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static __always_inline void cilium_dbg3(struct __ctx_buff *ctx, __u8 type,
					__u32 arg1, __u32 arg2, __u32 arg3)
{
	struct debug_msg msg = {
		__notify_common_hdr(CILIUM_NOTIFY_DBG_MSG, type),
		.arg1	= arg1,
		.arg2	= arg2,
		.arg3	= arg3,
	};

	ctx_event_output(ctx, &EVENTS_MAP, BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

struct debug_capture_msg {
	NOTIFY_CAPTURE_HDR
	__u32		arg1;
	__u32		arg2;
};

static __always_inline void cilium_dbg_capture2(struct __ctx_buff *ctx, __u8 type,
						__u32 arg1, __u32 arg2)
{
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, TRACE_PAYLOAD_LEN, ctx_len);
	struct debug_capture_msg msg = {
		__notify_common_hdr(CILIUM_NOTIFY_DBG_CAPTURE, type),
		__notify_pktcap_hdr(ctx_len, cap_len),
		.arg1	= arg1,
		.arg2	= arg2,
	};

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static __always_inline void cilium_dbg_capture(struct __ctx_buff *ctx, __u8 type,
					       __u32 arg1)
{
	cilium_dbg_capture2(ctx, type, arg1, 0);
}
#else
# define printk(fmt, ...)					\
		do { } while (0)

static __always_inline
void cilium_dbg(struct __ctx_buff *ctx __maybe_unused, __u8 type __maybe_unused,
		__u32 arg1 __maybe_unused, __u32 arg2 __maybe_unused)
{
}

static __always_inline
void cilium_dbg3(struct __ctx_buff *ctx __maybe_unused,
		 __u8 type __maybe_unused, __u32 arg1 __maybe_unused,
		 __u32 arg2 __maybe_unused, __u32 arg3 __maybe_unused)
{
}

static __always_inline
void cilium_dbg_capture(struct __ctx_buff *ctx __maybe_unused,
			__u8 type __maybe_unused, __u32 arg1 __maybe_unused)
{
}

static __always_inline
void cilium_dbg_capture2(struct __ctx_buff *ctx __maybe_unused,
			 __u8 type __maybe_unused, __u32 arg1 __maybe_unused,
			 __u32 arg2 __maybe_unused)
{
}

#endif
#endif /* __LIB_DBG__ */
