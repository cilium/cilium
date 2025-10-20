/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/compiler.h>
/* TODO: add SCTP */

/**
 * Flowtracer is a library that allows especially crafted (sentinel) packets
 * to flow through the datapath _as if_ they were real flow traffic (same
 * src/dst IP, protocol and src/dst L4 port), but executing commands while
 * traversing it. Commands can be used to force the execution of particular
 * code paths, collect debug information (traces) and metrics.
 *
 * Sentinel packets MUST be injected from a trusted source (e.g. from a worker
 * node, see WARNING note) and MUST be dropped before being delivered outside of
 * the system under test (e.g. before delivering the packet to a Pod).
 *
 * Injected sentinel packets have the following structure:
 *
 * +--------------------+
 * |       IP hdr       |
 * +--------------------+
 * |       L4 hdr       |
 * |   (TCP/UDP/SCTP)   |
 * +--------------------+
 * |   FlowTracer hdr   |
 * |   (list of cmds)   |
 * +--------------------+
 * |    Padding 0x0     |
 * //       ...        //  (Pre-alloced space for trace information)
 * |        0x0         |
 * +--------------------+
 *
 * L4 payload starts with the FlowTracer header and a padding region of up
 * to MTU - IP - L4 - FT hdr bytes, all set to 0x0. This space is used to
 * store trace information while traversing the datapath without the need to
 * call to bpf_xdp_adjust_tail()/ bpf_skb_change_tail(), changing L3/L4 hdr
 * (e.g. tot_len) and making sure L3/L4 csum is additive.
 *
 * Sentinel packets with trace data have the following structure:
 *
 * +--------------------+
 * |       IP hdr       |
 * +--------------------+
 * |       L4 hdr       |
 * |   (TCP/UDP/SCTP)   |
 * +--------------------+
 * |   FlowTracer hdr   |
 * |   (list of cmds)   |
 * +--------------------+
 * |  TLV: trace data1  |
 * +--------------------+
 * |  TLV: trace data2  |
 * +--------------------+
 * //       ...        //
 * +--------------------+
 * |    Padding 0x0     |
 * //       ...        //  (Pre-alloced space for trace information)
 * |        0x0         |
 * +--------------------+
 *
 * Sentinel packets MUST be dropped and logged (E.g. hubble, output to a debug
 * net device etc.) before making it to the final (flow) destination (E.g. a
 * Pod).
 *
 * Sentinel packets need to be clearly identified from real traffic. There are a
 * limited set of fields that can be (ab)used for this and that work for
 * TCP/UDP/SCTP:
 *
 * - DSCP/TOS: possible, but there is the risk that fabrics rewrite it if they
 *             do any kind of special QoS treatment (e.g. between worked nodes)
 *             Some public clouds (e.g. AWS may preserve them, but some like
 *             Azure might not).
 *
 * - Use a well-know port as a L4 src_port. Well behaved OSs should never use
 *   ports < 1024 as a src_port (sentinel). It is therefore easy to identify
 *   these packets as early as they are received. Then the original (> 1024)
 *   L4 src_port, part of the L4 payload, can be restored, but the packet can
 *   be marked as a sentinel.
 *
 *  Note that this has its nuances too:
 *     - NLBs and RSS will use the "sentinel" L4 src_port for flow hashing if
 *       the L4 src_port option is used. Most public clouds do. This is
 *       generally not an issue, as for real traffic src_port is random
 *       (`ip_local_port_range`), but if a particular path (e.g. node->node)
 *       wants to be replicating it might need some spraying.
 *
 *     - If packets traverse nodes (e.g. worker node to worker node) the
 *       sentinel src_port needs to be restored prior to TX (e.g. node->node).
 *
 * WARNING: Sentinel packets are a potential DOS vector. Untrusted flows must
 * be filter to avoid DoS attacks (e.g. with NACLs).
 */

#define FT_SENTINEL_MIN_PORT 0x0380 /* 896 */
#define FT_SENTINEL_MAX_PORT 0x03FF /* 1023 */

#define FT_MAX_TLV_LEN 9100 /* Verifier max val. clamping */

/**
 * TLV type
 */
enum ft_tlv_type {
	FT_TLV_INVALID       = 0,
	FT_TLV_PKT_INFO      = 1, /* SKB_BUFF info (queue_id, mark etc.)*/
	FT_TLV_ING_IFINDEX   = 2, /* Ingress interface */
	FT_TLV_EGR_IFINDEX   = 3, /* Egress interface */
	FT_TLV_CPU           = 4, /* CPU processing the packet */
	FT_TLV_ING_TS        = 5, /* Ingress timestamp */
	FT_TLV_EGR_TS        = 6, /* Egress timestamp */
	FT_TLV_PKT_SNAPSHOT  = 7, /* First N bytes packet snapshot */
	FT_TLV_DBG           = 8, /* DBG TLV */

	FT_TLV_NODE          = 9, /* Node wher tracing is happening */
	FT_TLV_LB_NODE       = 10, /* Selected backend's node */
	FT_TLV_LB_BACK       = 11  /* Selected backend */

	/* Add more... */
};

/**
 * Bitmap of FlowTracer commands
 */
enum ft_cmd {
	FT_CMD_TRACE_PKT_INFO    = (1 << FT_TLV_PKT_INFO),
	FT_CMD_TRACE_IIFINDEX    = (1 << FT_TLV_ING_IFINDEX),
	FT_CMD_TRACE_EIFINDEX    = (1 << FT_TLV_EGR_IFINDEX),
	FT_CMD_TRACE_CPU         = (1 << FT_TLV_CPU),
	FT_CMD_TRACE_ING_TS      = (1 << FT_TLV_ING_TS),
	FT_CMD_TRACE_EGR_TS      = (1 << FT_TLV_EGR_TS),
	FT_CMD_PKT_CAPTURE       = (1 << FT_TLV_PKT_SNAPSHOT),
	FT_CMD_DBG               = (1 << FT_TLV_DBG),

	FT_CMD_TRACE_NODE        = (1 << FT_TLV_NODE),
	FT_CMD_TRACE_LB_NODE     = (1 << FT_TLV_LB_NODE),
	FT_CMD_TRACE_LB_BACK     = (1 << FT_TLV_LB_BACK)
};

/**
 * Commands structure
 */
struct ft_cmds {
	__be32 cmds;        /* Commands bitmap */
	__be32 reserved[3]; /* TODO: reserved for cmd options */
} __packed;

/**
 * Basic Type+Length definition (out of the TLV)
 */
struct ft_tl {
	__be32 type;  /* enum ft_tlv_type */
	__u16 len;    /* Length in bytes including ft_tl */
	__u8 pad[2];  /* Align to 4 byte */
} __packed;

/**
 * Pkt info
 */
struct ft_tlv_info {
	struct ft_tl tl;

	__be32 trace_point;
	__be32 queue_id;
	__be32 pkt_type;
	__be32 hash;
	__be32 mark;
	__be32 gso_segs;
	__be32 gso_size;
} __packed;

/* Note: generics make BPF code easier. Use specifics for the client side */

/**
 * Generic 32 bit Value TLV
 */
struct ft_tlv_32 {
	struct ft_tl tl;

	__be32 trace_point;
	__be32 value;
} __packed;

/**
 * Generic 64 bit Value TLV
 */
struct ft_tlv_64 {
	struct ft_tl tl;

	__be32 trace_point;
	__be64 value;
} __packed;

/**
 * Ingress/egress ifindex TLV
 */
struct ft_tlv_iface {
	struct ft_tl tl;

	__be32 trace_point;
	__be32 ifindex;
} __packed;

/**
 * Processing CPU
 */
struct ft_tlv_cpu {
	struct ft_tl tl;

	__be32 trace_point;
	__be32 cpu;
} __packed;

/**
 * Timestamp trace
 */
struct ft_tlv_ts {
	struct ft_tl tl;

	__be32 trace_point;
	__be64 ts; /* Timestamp in ns from bpf_ktime_get_ns() */
} __packed;

/**
 * Packet snapshot
 *
 * Note: snaplen is part of tl->len (snaplen = tl->len - sizeof(struct ft_tl))
 */
struct ft_tlv_pkt_snap {
	struct ft_tl tl;

	__be32 trace_point;
	__u8 data[0];
} __packed;

/**
 * Debug TLV
 *
 * Debug TLV is an opaque TLV
 *
 * Note: debug info length is part of tl->len (dbg_len = tl->len -
 *       sizeof(struct ft_tl))
 *
 * XXX: is this really neeed? If you need to add support for this you might
 *      as well define your own TLV
 */
struct ft_tlv_dbg {
	struct ft_tl tl;

	__be32 trace_point;
	__u8 data[0];
} __packed;

enum ft_flags {
	FT_TRUNCATED = (1 << 0),
	FT_ERROR     = (1 << 1)
};

/**
 * Flowtracer header that is immediately after the L4 header (L4 payload)
 *
 * Note: l4_sport MUST be aligned to a power of 2.
 * Note2: tlvs_len is strictly not necessary but helps with logic. Also it's
 *        oversized to align to 4byte.
 */
struct ft_hdr {
	struct ft_cmds cmds;

	__be16 l4_sport;      /* (original) src port to be used for lookups */
	__u8   flags;
	__u8   pad;
	__be32 tlvs_len;     /* Size of all TLVs (bytes), aligned 4 bytes */
	struct ft_tl tlvs[0]; /* First TLV */
} __packed;

/**
 * Helper struct just to make code slightly cleaner
 * Note: TCP/UDP/SCTP all have the same src/dst port in the same place
 */
struct ft_l4_ports {
	__be16 sport;
	__be16 dport;
} __packed;

/**
 * Flowtracer context
 *
 * Note: this makes the implicit assumption that no tunneling will happen to
 * this point.
 *
 * TODO tracing encapsulated packets
 */
struct ft_ctx {
	bool parsed;
	bool tx_ready;
	__u16 l4_off;      /* Total offset from data to L4 hdr (ports) */
	__u16 l4_csum_off; /* Total offset from data to the L4 csum */
	__u16 ft_hdr_off;  /* Total offset from data to FT hdr */

	__be32 sum;        /* Accumulated L4 csum delta */
};

/**
 * Get the Flowtracer parsing context
 *
 * Static var which should end up in stack
 */
static __always_inline
struct ft_ctx *__ft_get(void)
{
	static struct ft_ctx ctx = {0};

	return &ctx;
}

static __always_inline
void ft_set_cmd(struct ft_hdr *hdr, const enum ft_cmd cmd)
{
	hdr->cmds.cmds = bpf_htonl(bpf_ntohl(hdr->cmds.cmds) | cmd);
}

static __always_inline
bool ft_has_cmd(struct ft_hdr *hdr, const enum ft_cmd cmd)
{
	return bpf_ntohl(hdr->cmds.cmds) & cmd;
}

static __always_inline
void ft_add_dbg_trace(struct __ctx_buff *ctx /*TODO*/)
{
	(void)ctx;
	/* TODO */
}

static __always_inline
void __ft_add_trace_uint(struct __ctx_buff *ctx, struct ft_ctx *ft,
			 struct ft_hdr *hdr, const enum ft_tlv_type type,
			 __u32 trace_point, const __u32 *value32,
			 const __u64 *value64)
{
	void *data_end = ctx_data_end(ctx);
	struct ft_tlv_32 *tlv;
	__be32 old_tlvs_len;
	__u16 tlvs_len;

	build_bug_on(sizeof(struct ft_tlv_32) != 16);
	build_bug_on(sizeof(struct ft_tlv_64) != 20);

	if (!value32 && !value64)
		return;

	old_tlvs_len = hdr->tlvs_len;
	tlvs_len = (__u16)bpf_ntohl(old_tlvs_len);

	/*
	 * clang optimizes tlvs_len with old_tlvs_len (32bit), so we need to
	 * clamp the max value so that the verifier doesn't complain.
	 */
	if (tlvs_len > FT_MAX_TLV_LEN)
		return;

	tlv = (struct ft_tlv_32 *)((void *)(hdr + 1) + tlvs_len);
	if ((void *)(tlv + 1) > data_end) {
		hdr->flags |= FT_TRUNCATED;
		return;
	}

	tlv->tl.type = bpf_htonl(type);
	tlv->trace_point = bpf_htonl(trace_point);

	if (value32) {
		tlv->value = bpf_htonl(*value32);
		tlv->tl.len = bpf_htons(sizeof(*tlv));
		tlvs_len += sizeof(*tlv);
		ft->sum = csum_diff(NULL, 0, tlv, sizeof(*tlv), ft->sum);
	} else {
		struct ft_tlv_64 *tlv64 = (struct ft_tlv_64 *)tlv;

		if ((void *)(tlv64 + 1) > data_end)
			goto ERR;

		tlv64->value = bpf_cpu_to_be64(*value64);
		tlv64->tl.len = bpf_htons(sizeof(*tlv64));
		tlvs_len += sizeof(*tlv64);
		ft->sum = csum_diff(NULL, 0, tlv64, sizeof(*tlv64), ft->sum);
	}

	hdr->tlvs_len = bpf_htonl(tlvs_len);
	ft->sum = csum_diff((__be32 *)&old_tlvs_len, 4,
			    (__be32 *)&hdr->tlvs_len, 4, ft->sum);

	return;
ERR:
	hdr->tlvs_len = old_tlvs_len;
	tlv->tl.type = 0;
	tlv->tl.len = 0;
	hdr->flags |= FT_ERROR;
}

static __always_inline
void ft_add_trace32(struct __ctx_buff *ctx, const enum ft_tlv_type type,
		    __u32 trace_point, const __u32 value)
{
#ifndef ENABLE_FLOWTRACER
	return;
#endif /* ENABLE_FLOWTRACER */

	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ft_ctx *ft = __ft_get();
	struct ft_hdr *hdr;

	/* Optimize for the non-sentinel pkt */
	if (likely(ft->ft_hdr_off == 0))
		return;

	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		return;

	if (!ft_has_cmd(hdr, (enum ft_cmd)(1 << type)))
		return;

	switch (type) {
	case FT_TLV_ING_IFINDEX:
	case FT_TLV_EGR_IFINDEX:
	case FT_TLV_CPU:
		break;
	default:
		return;
	}

	__ft_add_trace_uint(ctx, ft, hdr, type, trace_point, &value, NULL);
}

static __always_inline
void ft_add_trace64(struct __ctx_buff *ctx, const enum ft_tlv_type type,
		    __u32 trace_point, const __u64 value)
{
#ifndef ENABLE_FLOWTRACER
	return;
#endif /* ENABLE_FLOWTRACER */

	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ft_ctx *ft = __ft_get();
	struct ft_hdr *hdr;

	/* Optimize for the non-sentinel pkt */
	if (likely(ft->ft_hdr_off == 0))
		return;

	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		return;

	if (!ft_has_cmd(hdr, (enum ft_cmd)(1 << type)))
		return;

	switch (type) {
	case FT_TLV_ING_TS:
	case FT_TLV_EGR_TS:

	case FT_TLV_NODE:
	case FT_TLV_LB_NODE:
	case FT_TLV_LB_BACK:
		break;
	default:
		return;
	}

	__ft_add_trace_uint(ctx, ft, hdr, type, trace_point, NULL, &value);
}

static __always_inline
void ft_add_pkt_snap(struct __ctx_buff *ctx, __u32 trace_point, const __u16 len)
{
#ifndef ENABLE_FLOWTRACER
	return;
#endif /* ENABLE_FLOWTRACER */

	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ft_ctx *ft = __ft_get();
	struct ft_hdr *hdr;
	struct ft_tlv_pkt_snap *tlv;
	__be32 old_tlvs_len;
	void *snap;

	/* Optimize for the non-sentinel pkt */
	if (likely(ft->ft_hdr_off == 0))
		return;

	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		return;

	if (!ft_has_cmd(hdr, FT_CMD_PKT_CAPTURE))
		return;

	old_tlvs_len = hdr->tlvs_len;

	tlv = (struct ft_tlv_pkt_snap *)((void *)(hdr + 1) + bpf_ntohl(old_tlvs_len));
	if ((void *)(tlv + 1) > data_end) {
		hdr->flags |= FT_TRUNCATED;
		return;
	}

	snap = (void *)(tlv + 1);
	if ((snap + len) > data_end) {
		hdr->flags |= FT_TRUNCATED;
		return;
	}

	/* Append as TLV payload first len bytes of the pkt */
	/* Do this BEFORE adding the TLV */
	memcpy(snap, data, len);

	tlv->tl.type = bpf_htonl(FT_TLV_PKT_SNAPSHOT);
	tlv->tl.len = bpf_htons(sizeof(*tlv));
	tlv->trace_point = bpf_htonl(trace_point);
	old_tlvs_len = hdr->tlvs_len;

	hdr->tlvs_len = bpf_htonl(bpf_ntohl(old_tlvs_len) +
				     sizeof(*tlv) + len);
	ft->sum = csum_diff((__be32 *)&old_tlvs_len, 4,
			    (__be32 *)&hdr->tlvs_len, 4, ft->sum);
	ft->sum = csum_diff(NULL, 0, tlv, sizeof(*tlv), ft->sum);
	ft->sum = csum_diff(NULL, 0, data, len, ft->sum);
}

static __always_inline
int __ft_flip_l4_src_port(struct __ctx_buff *ctx, struct ft_ctx *ft,
			  struct ft_hdr *hdr)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ft_l4_ports *l4;
	__be16 tmp;

	if (!ft || !hdr)
		return -1;

	if (hdr->l4_sport == 0)
		return 0;

	l4 = (struct ft_l4_ports *)(data + ft->l4_off);
	if ((void *)(l4 + 1) > data_end)
		return -1;

	/**
	 * NOTE: this doesn't affect the L4 csum as the two values are
	 * flipped and both compute in the csum. For this to be true
	 * l4_sport needs to be aligned to a multiple of 2 byte offset.
	 */
	tmp = l4->sport;
	l4->sport = hdr->l4_sport;
	hdr->l4_sport = tmp;

	return 0;
}

static __always_inline
void __ft_intercept(struct __ctx_buff *ctx, const __u8 l4_proto,
		    const int l4_off)
{
	struct ft_ctx *ft = __ft_get();
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	__u16 sport;
	__u16 l4_size;
	struct ft_hdr *hdr;
	struct ft_l4_ports *l4;

	/* Optimize for the non-sentinel pkt */
	if (ft->parsed && likely(ft->ft_hdr_off == 0))
		return;

	ft->parsed = true;

	ft->l4_off = (__u16)l4_off;
	l4 = (struct ft_l4_ports *)(data + l4_off);
	if (((void *)(l4 + 1)) > data_end)
		return;

	sport = bpf_ntohs(l4->sport);

	/* TODO: implement DSCP intercepting mode */

	/* Skip FT packets as early as possible (hot) */
	if (likely(sport > FT_SENTINEL_MAX_PORT) ||
	    sport < FT_SENTINEL_MIN_PORT)
		return;

	ft->l4_csum_off = (__u16)l4_off;

	switch (l4_proto) {
	case IPPROTO_TCP:
		l4_size = sizeof(struct tcphdr);
		ft->l4_csum_off += offsetof(struct tcphdr, check);
		break;
	case IPPROTO_UDP:
		l4_size = sizeof(struct udphdr);
		ft->l4_csum_off += offsetof(struct udphdr, check);
		break;
	/* TODO case IPPROTO_SCTP: */
	default:
		return;
	}

	ft->ft_hdr_off = (__u16)l4_off + l4_size;
	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		goto ERR;

	if (__ft_flip_l4_src_port(ctx, ft, hdr) != 0)
		goto ERR;

	return;
ERR:
	ft->l4_off = 0;
	ft->l4_csum_off = 0;
	ft->ft_hdr_off = 0;
}

/**
 * Parses and caches the Flowtracer header if it's sentinel packet, else is a
 * no op.
 */
static __always_inline
void ft_intercept(struct __ctx_buff *ctx, const __u8 l4_proto, const int l4_off)
{
#ifndef ENABLE_FLOWTRACER
	return;
#endif /* ENABLE_FLOWTRACER */

	__ft_intercept(ctx, l4_proto, l4_off);
}

/**
 * Trap packet to CPU
 */
static __always_inline
void ft_trap(struct __ctx_buff *ctx)
{
#ifndef ENABLE_FLOWTRACER
	return;
#endif /* ENABLE_FLOWTRACER */

	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ft_ctx *ft = __ft_get();
	struct ft_hdr *hdr;
	__be16 *l4_sum;

	/* Optimize for the non-sentinel pkt */
	if (likely(ft->ft_hdr_off == 0))
		return;

	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		return;

	l4_sum = data + ft->l4_csum_off;
	if ((void *)(l4_sum + 1) > data_end)
		return;

	/* Adjust accumulated l4 csum */
	l4_csum_replace(ctx, ft->l4_csum_off, 0, ft->sum, BPF_F_PSEUDO_HDR);

	/* Prepare the message */
	/* XXX */
}

/**
 * Drop sentinel pkt
 */
static __always_inline
int ft_drop(struct __ctx_buff *ctx)
{
#ifndef ENABLE_FLOWTRACER
	return 0;
#endif /* ENABLE_FLOWTRACER */

	struct ft_ctx *ft = __ft_get();
	(void)ctx;

	/* Optimize for the non-sentinel pkt */
	if (likely(ft->ft_hdr_off == 0))
		return 0;

	return DROP_UNROUTABLE;
}

/**
 * Prepares the packet to be transmitted to another host (flips back src port)
 * if needed.
 *
 * This function is idempotent.
 */
static __always_inline
void ft_prep_tx(struct __ctx_buff *ctx)
{
#ifndef ENABLE_FLOWTRACER
	return;
#endif /* ENABLE_FLOWTRACER */

	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ft_ctx *ft = __ft_get();
	struct ft_hdr *hdr;
	__be16 *l4_sum;

	/* Optimize for the non-sentinel pkt */
	if (likely(ft->ft_hdr_off == 0) || ft->tx_ready)
		return;

	hdr = data + ft->ft_hdr_off;
	if ((void *)(hdr + 1) > data_end)
		return;

	l4_sum = data + ft->l4_csum_off;
	if ((void *)(l4_sum + 1) > data_end)
		return;

	if (__ft_flip_l4_src_port(ctx, ft, hdr) != 0)
		return;

	/* Adjust accumulated l4 csum */
	l4_csum_replace(ctx, ft->l4_csum_off, 0, ft->sum, BPF_F_PSEUDO_HDR);

	ft->tx_ready = true;
}
