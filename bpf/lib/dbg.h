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
	DBG_LB6_REVERSE_NAT_LOOKUP,
	DBG_LB6_REVERSE_NAT,
	DBG_LB4_LOOKUP_MASTER,
	DBG_LB4_LOOKUP_MASTER_FAIL,
	DBG_LB4_LOOKUP_SLAVE,
	DBG_LB4_LOOKUP_SLAVE_SUCCESS,
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
	DBG_CT_CREATED4,        /* arg1: (proxy_port << 16) | rev_nat_index
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
	DBG_CT_CREATED6,        /* arg1: (proxy_port << 16) | rev_nat_index
				 * arg2: src sec-id
				 * arg3: unused
				 */
	DBG_LB4_MASTER_HIT,	/* arg1: service ip
				 * arg2: service port
				 * arg3: number of backends found
				 */

	DBG_LB6_MASTER_HIT,	/* arg1: service ip (last 4 bytes)
				 * arg2: service port
				 * arg3: number of backends found
				 */
	DBG_ABORT_ERR,
};

/* Capture types */
enum {
	DBG_CAPTURE_UNSPEC,
	DBG_CAPTURE_FROM_LXC,
	DBG_CAPTURE_FROM_NETDEV,
	DBG_CAPTURE_FROM_OVERLAY,
	DBG_CAPTURE_DELIVERY,
	DBG_CAPTURE_FROM_LB,
	DBG_CAPTURE_AFTER_V46,
	DBG_CAPTURE_AFTER_V64,
	DBG_CAPTURE_PROXY_PRE,
	DBG_CAPTURE_PROXY_POST,
	DBG_CAPTURE_NAT,	/* packet going into SNAT box
				 * arg1: ingress ifindex of SNAT box
				 */
	DBG_CAPTURE_NAT_REV,	/* packet going into reverse SNAT box
				 * arg1: ingress ifindex of reverse SNAT box
				 */
	DBG_CAPTURE_NAT_REV_OUT, /* bpf_nat_rev_out.c
				  * arg1: revnat index stored in skb->mark
				  */
	DBG_CAPTURE_FROM_NAT,	 /* bpf_netdev.c (when compiled with FROM_NAT)
				  * arg1: ingress ifindex of where the bpf_netdev is attached to
				  */
	DBG_CAPTURE_FROM_HOST,	 /* bpf_host_pre.o - packet is coming from host
				  * arg1: egress ifindex
				  */
};

#ifndef EVENT_SOURCE
#define EVENT_SOURCE 0
#endif

#if defined DEBUG || defined ENABLE_TRACE
#include "events.h"
#endif

#ifdef DEBUG
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

static inline void cilium_trace(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
{
	uint32_t hash = get_hash_recalc(skb);
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

static inline void cilium_trace3(struct __sk_buff *skb, __u8 type, __u32 arg1,
				 __u32 arg2, __u32 arg3)
{
	uint32_t hash = get_hash_recalc(skb);
	struct debug_msg msg = {
		.type = CILIUM_NOTIFY_DBG_MSG,
		.subtype = type,
		.source = EVENT_SOURCE,
		.hash = hash,
		.arg1 = arg1,
		.arg2 = arg2,
		.arg3 = arg3,
	};

	skb_event_output(skb, &cilium_events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
}

#else
# define printk(fmt, ...)					\
		do { } while (0)

static inline void cilium_trace(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
{
}

static inline void cilium_trace3(struct __sk_buff *skb, __u8 type, __u32 arg1,
				 __u32 arg2, __u32 arg3)
{
}

#endif

#ifdef ENABLE_TRACE

#ifndef TRACE_PAYLOAD_LEN
#define TRACE_PAYLOAD_LEN 128ULL
#endif

struct debug_capture_msg {
	NOTIFY_COMMON_HDR
	__u32		len_orig;
	__u32		len_cap;
	__u32		arg1;
	__u32		arg2;
};

static inline void cilium_trace_capture2(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
{
	uint64_t skb_len = skb->len, cap_len = min(TRACE_PAYLOAD_LEN, skb_len);
	uint32_t hash = get_hash_recalc(skb);
	struct debug_capture_msg msg = {
		.type = CILIUM_NOTIFY_DBG_CAPTURE,
		.subtype = type,
		.source = EVENT_SOURCE,
		.hash = hash,
		.len_orig = skb_len,
		.len_cap = cap_len,
		.arg1 = arg1,
		.arg2 = arg2,
	};

	skb_event_output(skb, &cilium_events,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static inline void cilium_trace_capture(struct __sk_buff *skb, __u8 type, __u32 arg1)
{
	return cilium_trace_capture2(skb, type, arg1, 0);
}

#else /* ENABLE_TRACE */

static inline void cilium_trace_capture(struct __sk_buff *skb, __u8 type, __u32 arg1)
{
}

static inline void cilium_trace_capture2(struct __sk_buff *skb, __u8 type, __u32 arg1, __u32 arg2)
{
}

#endif /* ENABLE_TRACE */


#endif /* __LIB_DBG__ */
