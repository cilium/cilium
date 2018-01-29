/*
 *  Copyright (C) 2016-2017 Authors of Cilium
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
/*
 * Packet forwarding notification via perf event ring buffer.
 *
 * API:
 * void send_trace_notify(skb, obs_point, src, dst, dst_id, ifindex)
 *
 * If TRACE_NOTIFY is not defined, the API will be compiled in as a NOP.
 */

#ifndef __LIB_TRACE__
#define __LIB_TRACE__

#include "dbg.h"
#include "events.h"
#include "common.h"
#include "utils.h"

/* Available observation points. */
enum {
	TRACE_TO_LXC,
	TRACE_TO_PROXY,
	TRACE_TO_HOST,
	TRACE_TO_STACK,
	TRACE_TO_OVERLAY,
	TRACE_FROM_LXC,
	TRACE_FROM_PROXY,
	TRACE_FROM_HOST,
	TRACE_FROM_STACK,
	TRACE_FROM_OVERLAY,
};

/* Reasons for forwarding a packet. */
enum {
	TRACE_REASON_POLICY = CT_NEW,
	TRACE_REASON_CT_ESTABLISHED = CT_ESTABLISHED,
	TRACE_REASON_CT_REPLY = CT_REPLY,
	TRACE_REASON_CT_RELATED = CT_RELATED,
};

#ifdef TRACE_NOTIFY

struct trace_notify {
	NOTIFY_COMMON_HDR
	__u32		len_orig;
	__u32		len_cap;
	__u32		src_label;
	__u32		dst_label;
	__u16		dst_id;
	__u8		reason;
	__u8		pad;
	__u32		ifindex;
};

/**
 * send_trace_notify
 * @skb:	socket buffer
 * @obs_point:	observation point (TRACE_*)
 * @src:	source identity
 * @dst:	destination identity
 * @dst_id:	designated destination endpoint ID
 * @ifindex:	designated destination ifindex
 * @reason:	reason for forwarding the packet (TRACE_REASON_*)
 *
 * Generate a notification to indicate a packet was forwarded at an observation point.
 */
static inline void send_trace_notify(struct __sk_buff *skb, __u8 obs_point, __u32 src, __u32 dst,
				     __u16 dst_id, __u32 ifindex, __u8 reason)
{
	uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
	uint32_t hash = get_hash_recalc(skb);
	struct trace_notify msg = {
		.type = CILIUM_NOTIFY_TRACE,
		.subtype = obs_point,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.src_label = src,
		.dst_label = dst,
		.dst_id = dst_id,
		.reason = reason,
		.pad = 0,
		.ifindex = ifindex,
	};

	skb_event_output(skb, &cilium_events,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

#else

static inline void send_trace_notify(struct __sk_buff *skb, __u8 obs_point, __u32 src, __u32 dst,
				     __u16 dst_id, __u32 ifindex, __u8 reason)
{
}

#endif

#endif /* __LIB_TRACE__ */
