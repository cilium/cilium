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
 * Drop & error notification via perf event ring buffer
 *
 * API:
 * int send_drop_notify(skb, src, dst, dst_id, ifindex, reason, exitcode,
                        __u8 direction)
 * int send_drop_notify_error(skb, error, exitcode, __u8 direction)
 *
 * If DROP_NOTIFY is not defined, the API will be compiled in as a NOP.
 */

#ifndef __LIB_DROP__
#define __LIB_DROP__

#include "dbg.h"
#include "events.h"
#include "common.h"
#include "utils.h"
#include "metrics.h"

#ifdef DROP_NOTIFY

struct drop_notify {
	NOTIFY_COMMON_HDR
	__u32		len_orig;
	__u32		len_cap;
	__u32		src_label;
	__u32		dst_label;
	__u32		dst_id;
	__u32		ifindex;
};

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_DROP_NOTIFY) int __send_drop_notify(struct __sk_buff *skb)
{
	uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
	uint32_t hash = get_hash_recalc(skb);
	uint32_t srcdst_info = skb->cb[1];
	struct drop_notify msg = {
		.type = CILIUM_NOTIFY_DROP,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.src_label = srcdst_info >> 16,
		.dst_label = srcdst_info & 0xFFFF,
		.dst_id = skb->cb[3],
		.ifindex = skb->cb[4],
	};
	int error = skb->cb[2];

	if (error < 0)
		error = -error;

	msg.subtype = error;

	skb_event_output(skb, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));

	return skb->cb[0];
}

/**
 * send_drop_notify
 * @skb:	socket buffer
 * @src:	source identity
 * @dst:	destination identity
 * @dst_id:	designated destination endpoint ID
 * @ifindex:	designated destination ifindex
 * @reason:	Reason for drop
 * @exitcode:	error code to return to the kernel
 *
 * Generate a notification to indicate a packet was dropped.
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
static inline int send_drop_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				   __u32 dst_id, __u32 ifindex, int reason,
				   int exitcode, __u8 direction)
{
	skb->cb[0] = exitcode;
	skb->cb[1] = (src << 16) | (dst & 0xFFFF);
	skb->cb[2] = reason;
	skb->cb[3] = dst_id;
	skb->cb[4] = ifindex,

	update_metrics(skb->len, direction, -reason);

	ep_tail_call(skb, CILIUM_CALL_DROP_NOTIFY);

	return exitcode;
}

#else

static inline int send_drop_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				   __u32 dst_id, __u32 ifindex, int reason,
				   int exitcode, __u8 direction)
{
	update_metrics(skb->len, direction, -reason);
	return exitcode;
}

#endif

static inline int send_drop_notify_error(struct __sk_buff *skb, int error,
                                         int exitcode, __u8 direction)
{
	return send_drop_notify(skb, 0, 0, 0, 0, error, exitcode, direction);
}

#endif /* __LIB_DROP__ */
