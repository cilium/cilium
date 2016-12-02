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
/*
 * Drop & error notification via perf event ring buffer
 *
 * API:
 * int send_drop_notify(skb, src, dst, dst_id, ifindex, exitcode)
 * int send_drop_notify_error(skb, error, exitcode)
 *
 * Both functions are implemented as terminal calls and will cause the BPF
 * program to terminate after execution.
 *
 * If DROP_NOTIFY is not defined, the API will be compiled in as a NOP.
 */

#ifndef __LIB_DROP__
#define __LIB_DROP__

#include "dbg.h"
#include "events.h"
#include "common.h"
#include "utils.h"

#ifdef DROP_NOTIFY
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_ERROR_NOTIFY) int __send_error_notify(struct __sk_buff *skb)
{
	uint64_t skb_len = skb->len, cap_len = min(128ULL, skb_len);
	uint32_t hash = get_hash_recalc(skb);
	struct drop_notify msg = {
		.type = CILIUM_NOTIFY_DROP,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.ifindex = skb->ingress_ifindex,
	};
	int error = skb->cb[1];

	if (error < 0)
		error = -error;

	msg.subtype = error;

	skb_event_output(skb, &cilium_events,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));

	return skb->cb[0];
}

/**
 * send_drop_notify_error
 * @skb:	socket buffer
 * @error:	error code to be returned
 * @exitcode:	error code to return to the kernel
 *
 * Generate a notification to indicate a packet was dropped due to an error
 * condition while parsing and processing the packet. Use send_drop_notify()
 * instead for any policy related drops.
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
static inline int send_drop_notify_error(struct __sk_buff *skb, int error, int exitcode)
{
	if (IS_ERR(error)) {
		skb->cb[0] = exitcode;
		skb->cb[1] = error;

		tail_call(skb, &cilium_calls, CILIUM_CALL_ERROR_NOTIFY);

		return exitcode;
	}

	/* No error condition, return original return code */
	return error;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_DROP_NOTIFY) int __send_drop_notify(struct __sk_buff *skb)
{
	uint64_t skb_len = skb->len, cap_len = min(64ULL, skb_len);
	uint32_t hash = get_hash_recalc(skb);
	struct drop_notify msg = {
		.type = CILIUM_NOTIFY_DROP,
		.subtype = -(DROP_POLICY),
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.src_label = skb->cb[1],
		.dst_label = skb->cb[2],
		.dst_id = skb->cb[3],
		.ifindex = skb->cb[4],
	};

	skb_event_output(skb, &cilium_events,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));

	return skb->cb[0];
}

/**
 * send_drop_notify
 * @skb:	socket buffer
 * @src:	source context ID
 * @dst:	destination context ID
 * @dst_id:	designated destination container ID
 * @ifindex:	designated destination ifindex
 * @exitcode:	error code to return to the kernel
 *
 * Generate a notification to indicate a packet was dropped due to a policy
 * violation. Use send_drop_notify_error() for any generic error related
 * packet drops instead.
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
static inline int send_drop_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				   __u32 dst_id, __u32 ifindex, int exitcode)
{
	skb->cb[0] = exitcode;
	skb->cb[1] = src;
	skb->cb[2] = dst;
	skb->cb[3] = dst_id;
	skb->cb[4] = ifindex,

	tail_call(skb, &cilium_calls, CILIUM_CALL_DROP_NOTIFY);

	return exitcode;
}
#else
static inline int send_drop_notify_error(struct __sk_buff *skb, int error, int exitcode)
{
	return exitcode;
}

static inline int send_drop_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				    __u32 dst_id, __u32 ifindex, int exitcode)
{
	return exitcode;
}
#endif

#endif /* __LIB_DROP__ */
