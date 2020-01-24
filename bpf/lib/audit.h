/*
 *  Copyright (C) 2016-2019 Authors of Cilium
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
 * Policy audit notification via perf event ring buffer
 *
 * API:
 * int send_audit_notify(skb, src, dst, dst_id, reason, direction)
 *
 * If AUDIT_NOTIFY is not defined, the API will be compiled in as a NOP.
 */

#ifndef __LIB_AUDIT__
#define __LIB_AUDIT__

#include "dbg.h"
#include "drop.h"
#include "events.h"
#include "common.h"
#include "utils.h"
#include "metrics.h"

#ifdef AUDIT_NOTIFY

/**
 * send_audit_notify
 * @skb:	socket buffer
 * @src:	source identity
 * @dst:	destination identity
 * @dst_id:	designated destination endpoint ID
 * @reason:	reason for drop
 * @direction:	packet direction
 *
 * Generate a notification to indicate a packet was allowed due to the audit mode.
 */
static inline void send_audit_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				     __u32 dst_id, int reason, __u8 direction)
{
	update_metrics(skb->len, direction, -reason);

	uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
	uint32_t hash = get_hash_recalc(skb);
	struct drop_notify msg = {
		.type = CILIUM_NOTIFY_AUDIT,
		.subtype = -reason,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.version = NOTIFY_CAPTURE_VER,
		.src_label = src,
		.dst_label = dst,
		.dst_id = dst_id,
		.unused = 0,
	};
	skb_event_output(skb, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

#else

static inline void send_audit_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				     __u32 dst_id, int reason, __u8 direction)
{
	update_metrics(skb->len, direction, -reason);
}

#endif

#endif /* __LIB_AUDIT__ */
