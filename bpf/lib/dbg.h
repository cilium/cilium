/*
 *  Copyright (C) 2016 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
	DBG_CT_LOOKUP,
	DBG_CT_MATCH,
	DBG_CT_CREATED,
	DBG_CT_CREATED2,
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
	DBG_LB6_REVERSE_NAT_LOOKUP,
	DBG_LB6_REVERSE_NAT,
	DBG_LB4_LOOKUP_MASTER,
	DBG_LB4_LOOKUP_MASTER_FAIL,
	DBG_LB4_LOOKUP_SLAVE,
	DBG_LB4_LOOKUP_SLAVE_SUCCESS,
	DBG_LB4_REVERSE_NAT_LOOKUP,
	DBG_LB4_REVERSE_NAT,
};

/* Capture types */
enum {
	DBG_CAPTURE_UNSPEC,
	DBG_CAPTURE_FROM_LXC,
	DBG_CAPTURE_FROM_NETDEV,
	DBG_CAPTURE_FROM_OVERLAY,
	DBG_CAPTURE_DELIVERY,
	DBG_CAPTURE_FROM_LB,
};

static inline uint32_t __inline__ get_packet_marker(struct __sk_buff *skb)
{
	uint32_t marker = skb->mark;
	if (!marker)
		marker = skb->hash;

	return marker;
}

#ifdef DEBUG
#include "events.h"
#include "utils.h"

# define printk(fmt, ...)					\
		({						\
			char ____fmt[] = fmt;			\
			trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);		\
		})

#ifndef EVENT_SOURCE
#define EVENT_SOURCE 0
#endif

struct debug_msg {
	NOTIFY_COMMON_HDR
	__u32		arg1;
	__u32		arg2;
	__u32		pad;
};

struct debug_capture_msg {
	NOTIFY_COMMON_HDR
	__u32		len_orig;
	__u32		len_cap;
	__u32		arg1;
};

static inline void cilium_trace(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
{
	uint32_t hash = get_packet_marker(skb);
	struct debug_msg msg = {
		.type = CILIUM_NOTIFY_DBG_MSG,
		.subtype = type,
		.source = EVENT_SOURCE,
		.hash = hash,
		.arg1 = arg1,
		.arg2 = arg2,
	};

	skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
}

static inline void cilium_trace_capture(struct __sk_buff *skb, __u8 type, __u32 arg1)
{
	uint64_t skb_len = skb->len, cap_len = min(128ULL, skb_len);
	uint32_t hash = get_packet_marker(skb);
	struct debug_capture_msg msg = {
		.type = CILIUM_NOTIFY_DBG_CAPTURE,
		.subtype = type,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.arg1 = arg1,
	};

	skb_event_output(skb, &cilium_events,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static inline void __inline__ add_packet_tracer(struct __sk_buff *skb)
{
	uint32_t rnd = get_prandom_u32();
	skb->mark = rnd;
}

#else
# define printk(fmt, ...)					\
		do { } while (0)

static inline void cilium_trace(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
{
}

static inline void cilium_trace_capture(struct __sk_buff *skb, __u8 type, __u32 arg1)
{
}

static inline void __inline__ add_packet_tracer(struct __sk_buff *skb)
{
}
#endif

#endif /* __LIB_DBG__ */
