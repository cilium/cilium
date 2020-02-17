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
 * void send_trace_notify(skb, obs_point, src, dst, dst_id, ifindex, reason, monitor)
 *
 * If TRACE_NOTIFY is not defined, the API will be compiled in as a NOP.
 */

#ifndef __LIB_TRACE__
#define __LIB_TRACE__

#include "dbg.h"
#include "events.h"
#include "common.h"
#include "utils.h"
#include "metrics.h"

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
	TRACE_FROM_NETWORK,
};

/* Reasons for forwarding a packet. */
enum {
	TRACE_REASON_POLICY = CT_NEW,
	TRACE_REASON_CT_ESTABLISHED = CT_ESTABLISHED,
	TRACE_REASON_CT_REPLY = CT_REPLY,
	TRACE_REASON_CT_RELATED = CT_RELATED,
};

#define TRACE_REASON_ENCRYPTED	    0x80

/* Trace aggregation levels. */
enum {
	TRACE_AGGREGATE_NONE = 0,      /* Trace every packet on rx & tx */
	TRACE_AGGREGATE_RX = 1,        /* Hide trace on packet receive */
	TRACE_AGGREGATE_ACTIVE_CT = 3, /* Ratelimit active connection traces */
};

#ifndef MONITOR_AGGREGATION
#define MONITOR_AGGREGATION TRACE_AGGREGATE_NONE
#endif

/**
 * update_trace_metrics
 * @skb:	socket buffer
 * @obs_point:	observation point (TRACE_*)
 * @reason:	reason for forwarding the packet (TRACE_REASON_*)
 *
 * Update metrics based on a trace event
 */
static inline void
update_trace_metrics(struct __sk_buff *skb, __u8 obs_point, __u8 reason)
{
	__u8 encrypted;

	switch (obs_point) {
		case TRACE_TO_LXC:
			update_metrics(skb->len, METRIC_INGRESS, REASON_FORWARDED);
			break;

		/* TRACE_FROM_LXC, i.e endpoint-to-endpoint delivery
		 * is handled separately in ipv*_local_delivery() where we can bump
		 * an egress forward. It could still be dropped but it would show
		 * up later as an ingress drop, in that scenario.
		 *
		 * TRACE_TO_PROXY is not handled in datapath. This is because we have separate
		 * L7 proxy "forwarded" and "dropped" (ingress/egress) counters in the proxy layer
		 * to capture these metrics.
		 */
		case TRACE_TO_HOST:
		case TRACE_TO_STACK:
		case TRACE_TO_OVERLAY:
			update_metrics(skb->len, METRIC_EGRESS, REASON_FORWARDED);
			break;
		case TRACE_FROM_OVERLAY:
		case TRACE_FROM_NETWORK:
			encrypted = reason & TRACE_REASON_ENCRYPTED;
			if (!encrypted)
				update_metrics(skb->len, METRIC_INGRESS, REASON_PLAINTEXT);
			else
				update_metrics(skb->len, METRIC_INGRESS, REASON_DECRYPT);
			break;
	}
}

#ifdef TRACE_NOTIFY

struct trace_notify {
	NOTIFY_CAPTURE_HDR
	__u32		src_label;
	__u32		dst_label;
	__u16		dst_id;
	__u8		reason;
	__u8		ipv6:1;
	__u8		pad:7;
	__u32		ifindex;
	union {
		struct {
			__be32		orig_ip4;
			__u32		orig_pad1;
			__u32		orig_pad2;
			__u32		orig_pad3;
		};
		union v6addr	orig_ip6;
	};
};

static inline bool emit_trace_notify(__u8 obs_point, __u32 monitor)
{
	if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_RX) {
		switch (obs_point) {
		case TRACE_FROM_LXC:
		case TRACE_FROM_PROXY:
		case TRACE_FROM_HOST:
		case TRACE_FROM_STACK:
		case TRACE_FROM_OVERLAY:
			return false;
		default:
			break;
		}
	}

	if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_ACTIVE_CT && !monitor)
		return false;

	return true;
}

static inline void
send_trace_notify(struct __sk_buff *skb, __u8 obs_point, __u32 src, __u32 dst,
		   __u16 dst_id, __u32 ifindex, __u8 reason, __u32 monitor)
{
	update_trace_metrics(skb, obs_point, reason);

	if (!emit_trace_notify(obs_point, monitor))
		return;

	if (!monitor)
		monitor = TRACE_PAYLOAD_LEN;

	__u64 skb_len = (__u64)skb->len, cap_len = min((__u64)monitor, (__u64)skb_len);
	__u32 hash = get_hash_recalc(skb);
	struct trace_notify msg = {
		.type = CILIUM_NOTIFY_TRACE,
		.subtype = obs_point,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.version = NOTIFY_CAPTURE_VER,
		.src_label = src,
		.dst_label = dst,
		.dst_id = dst_id,
		.reason = reason,
		.ipv6 = 0,
		.pad = 0,
		.ifindex = ifindex,
		.orig_ip4 = 0,
		.orig_pad1 = 0,
		.orig_pad2 = 0,
		.orig_pad3 = 0,
	};
	skb_event_output(skb, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static inline void
send_trace_notify4(struct __sk_buff *skb, __u8 obs_point, __u32 src, __u32 dst, __be32 orig_addr,
		   __u16 dst_id, __u32 ifindex, __u8 reason, __u32 monitor)
{
	update_trace_metrics(skb, obs_point, reason);

	if (!emit_trace_notify(obs_point, monitor))
		return;

	if (!monitor)
		monitor = TRACE_PAYLOAD_LEN;

	__u64 skb_len = (__u64)skb->len, cap_len = min((__u64)monitor, (__u64)skb_len);
	__u32 hash = get_hash_recalc(skb);
	struct trace_notify msg = {
		.type = CILIUM_NOTIFY_TRACE,
		.subtype = obs_point,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.version = NOTIFY_CAPTURE_VER,
		.src_label = src,
		.dst_label = dst,
		.dst_id = dst_id,
		.reason = reason,
		.ipv6 = 0,
		.pad = 0,
		.ifindex = ifindex,
		.orig_ip4 = orig_addr,
		.orig_pad1 = 0,
		.orig_pad2 = 0,
		.orig_pad3 = 0,
	};
	skb_event_output(skb, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static inline void
send_trace_notify6(struct __sk_buff *skb, __u8 obs_point, __u32 src, __u32 dst, union v6addr *orig_addr,
		   __u16 dst_id, __u32 ifindex, __u8 reason, __u32 monitor)
{
	update_trace_metrics(skb, obs_point, reason);

	if (!emit_trace_notify(obs_point, monitor))
		return;

	if (!monitor)
		monitor = TRACE_PAYLOAD_LEN;

	__u64 skb_len = (__u64)skb->len, cap_len = min((__u64)monitor, (__u64)skb_len);
	__u32 hash = get_hash_recalc(skb);
	struct trace_notify msg = {
		.type = CILIUM_NOTIFY_TRACE,
		.subtype = obs_point,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.version = NOTIFY_CAPTURE_VER,
		.src_label = src,
		.dst_label = dst,
		.dst_id = dst_id,
		.reason = reason,
		.ipv6 = 1,
		.pad = 0,
		.ifindex = ifindex,
	};

	ipv6_addr_copy(&msg.orig_ip6, orig_addr);

	skb_event_output(skb, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

#else

static inline void
send_trace_notify(struct __sk_buff *skb, __u8 obs_point, __u32 src, __u32 dst,
		  __u16 dst_id, __u32 ifindex, __u8 reason, __u32 monitor)
{
	update_trace_metrics(skb, obs_point, reason);
}

static inline void
send_trace_notify4(struct __sk_buff *skb, __u8 obs_point, __u32 src, __u32 dst, __be32 orig_addr,
		   __u16 dst_id, __u32 ifindex, __u8 reason, __u32 monitor)
{
	update_trace_metrics(skb, obs_point, reason);
}

static inline void
send_trace_notify6(struct __sk_buff *skb, __u8 obs_point, __u32 src, __u32 dst, union v6addr *orig_addr,
		   __u16 dst_id, __u32 ifindex, __u8 reason, __u32 monitor)
{
	update_trace_metrics(skb, obs_point, reason);
}

#endif

#endif /* __LIB_TRACE__ */
