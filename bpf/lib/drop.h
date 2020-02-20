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
 * Drop & error notification via perf event ring buffer
 *
 * API:
 * int send_drop_notify(skb, src, dst, dst_id, reason, exitcode, __u8 direction)
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
	NOTIFY_CAPTURE_HDR
	__u32		src_label;
	__u32		dst_label;
	__u32		dst_id;
	__u32		unused;
};

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_DROP_NOTIFY) int __send_drop_notify(struct __sk_buff *skb)
{
	__u64 skb_len = (__u64)skb->len, cap_len = min((__u64)TRACE_PAYLOAD_LEN, (__u64)skb_len);
	__u32 hash = get_hash_recalc(skb);
	struct drop_notify msg = {
		.type = CILIUM_NOTIFY_DROP,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.version = NOTIFY_CAPTURE_VER,
		.src_label = skb->cb[0],
		.dst_label = skb->cb[1],
		.dst_id = skb->cb[3],
		.unused = 0,
	};
	// mask needed to calm verifier
	int error = skb->cb[2] & 0xFFFFFFFF;

	if (error < 0)
		error = -error;

	msg.subtype = error;

	skb_event_output(skb, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));

	return skb->cb[4];
}

/**
 * send_drop_notify
 * @skb:	socket buffer
 * @src:	source identity
 * @dst:	destination identity
 * @dst_id:	designated destination endpoint ID
 * @reason:	Reason for drop
 * @exitcode:	error code to return to the kernel
 *
 * Generate a notification to indicate a packet was dropped.
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
static inline int send_drop_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				   __u32 dst_id, int reason, int exitcode, __u8 direction)
{
	skb->cb[0] = src;
	skb->cb[1] = dst;
	skb->cb[2] = reason;
	skb->cb[3] = dst_id;
	skb->cb[4] = exitcode;

	update_metrics(skb->len, direction, -reason);

	ep_tail_call(skb, CILIUM_CALL_DROP_NOTIFY);

	return exitcode;
}

#else

static inline int send_drop_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				   __u32 dst_id, int reason, int exitcode, __u8 direction)
{
	update_metrics(skb->len, direction, -reason);
	return exitcode;
}

#endif

static inline int send_drop_notify_error(struct __sk_buff *skb, __u32 src, int error,
                                         int exitcode, __u8 direction)
{
	return send_drop_notify(skb, src, 0, 0, error, exitcode, direction);
}

#endif /* __LIB_DROP__ */
