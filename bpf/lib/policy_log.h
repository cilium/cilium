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
 * Packet forwarding notification via perf event ring buffer.
 *
 * API:
 * void send_policy_notify4(skb, remote_label, dir, action)
 *
 * Todo: add DROP_NOTOFY build option
 */

#ifndef __LIB_POLICY_LOG__
#define __LIB_POLICY_LOG__

#include "common.h"

#ifdef POLICY_NOTIFY
struct policy_log_notify {
	NOTIFY_CAPTURE_HDR
	__u32	remote_label;
	__u8	action;
	__u8	dir:2,
		ipv6:1,
		pad:5;
	__u16	pads;
};

static inline void
send_policy_notify4(struct __sk_buff *skb, __u32 remote_label, __u8 dir, __u8 action)
{
	uint64_t skb_len = (uint64_t)skb->len, cap_len = min((uint64_t)TRACE_PAYLOAD_LEN, (uint64_t)skb_len);
	uint32_t hash = get_hash_recalc(skb);
	struct policy_log_notify msg = {
		.type = CILIUM_NOTIFY_POLICY,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.remote_label = remote_label,
		.action = action,
		.dir = dir,
		.ipv6 = 0,
		.pad = 0,
		.pads = 0,
	};
	skb_event_output(skb, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

#endif

#endif /* __LIB_POLICY_LOG__*/
