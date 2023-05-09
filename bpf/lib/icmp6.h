/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#if !defined(__LIB_ICMP6__) && defined(ENABLE_IPV6)
#define __LIB_ICMP6__

#include <linux/icmpv6.h>
#include <linux/in.h>
#include "common.h"
#include "eth.h"
#include "drop.h"
#include "eps.h"

#define ICMP6_TYPE_OFFSET (sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_type))
#define ICMP6_CSUM_OFFSET (sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_cksum))
#define ICMP6_ND_TARGET_OFFSET (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))
#define ICMP6_ND_OPTS (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + sizeof(struct in6_addr))

#define ICMP6_UNREACH_MSG_TYPE		1
#define ICMP6_PARAM_ERR_MSG_TYPE	4
#define ICMP6_ECHO_REQUEST_MSG_TYPE	128
#define ICMP6_ECHO_REPLY_MSG_TYPE	129
#define ICMP6_MULT_LIST_QUERY_TYPE	130
#define ICMP6_NS_MSG_TYPE		135
#define ICMP6_NA_MSG_TYPE		136
#define ICMP6_RR_MSG_TYPE		138
#define ICMP6_INV_NS_MSG_TYPE		141
#define ICMP6_MULT_LIST_REPORT_V2_TYPE	143
#define ICMP6_SEND_NS_MSG_TYPE		148
#define ICMP6_SEND_NA_MSG_TYPE		149
#define ICMP6_MULT_RA_MSG_TYPE		151
#define ICMP6_MULT_RT_MSG_TYPE		153

#define SKIP_HOST_FIREWALL	-2

/* If no specific action is specified, drop unknown neighbour solicitation
 * messages.
 */
#ifndef ACTION_UNKNOWN_ICMP6_NS
#define ACTION_UNKNOWN_ICMP6_NS DROP_UNKNOWN_TARGET
#endif

static __always_inline __u8 icmp6_load_type(struct __ctx_buff *ctx, int nh_off)
{
	__u8 type;

	ctx_load_bytes(ctx, nh_off + ICMP6_TYPE_OFFSET, &type, sizeof(type));
	return type;
}

static __always_inline int icmp6_send_reply(struct __ctx_buff *ctx, int nh_off)
{
	union macaddr smac, dmac = NODE_MAC;
	const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	union v6addr sip, dip, router_ip;
	__be32 sum;

	if (ipv6_load_saddr(ctx, nh_off, &sip) < 0 ||
	    ipv6_load_daddr(ctx, nh_off, &dip) < 0)
		return DROP_INVALID;

	BPF_V6(router_ip, ROUTER_IP);
	/* ctx->saddr = ctx->daddr */
	if (ipv6_store_saddr(ctx, router_ip.addr, nh_off) < 0)
		return DROP_WRITE_ERROR;
	/* ctx->daddr = ctx->saddr */
	if (ipv6_store_daddr(ctx, sip.addr, nh_off) < 0)
		return DROP_WRITE_ERROR;

	/* fixup checksums */
	sum = csum_diff(sip.addr, 16, router_ip.addr, 16, 0);
	if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	sum = csum_diff(dip.addr, 16, sip.addr, 16, 0);
	if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	/* dmac = smac, smac = dmac */
	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		return DROP_INVALID;

	if (eth_store_daddr(ctx, smac.addr, 0) < 0 ||
	    eth_store_saddr(ctx, dmac.addr, 0) < 0)
		return DROP_WRITE_ERROR;

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, ctx_get_ifindex(ctx));

	return redirect_self(ctx);
}

/*
 * send_icmp6_ndisc_adv
 * @ctx:	socket buffer
 * @nh_off:	offset to the IPv6 header
 * @mac:	device mac address
 * @to_router:	ndisc is sent to router, otherwise ndisc is sent to an endpoint.
 *
 * Send an ICMPv6 nadv reply in return to an ICMPv6 ndisc.
 */
static __always_inline int
send_icmp6_ndisc_adv(struct __ctx_buff *ctx, int nh_off,
		     const union macaddr *mac, bool to_router)
{
	struct icmp6hdr icmp6hdr __align_stack_8 = {}, icmp6hdr_old __align_stack_8;
	__u8 opts[8], opts_old[8];
	const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	__be32 sum;

	if (ctx_load_bytes(ctx, nh_off + sizeof(struct ipv6hdr), &icmp6hdr_old,
			   sizeof(icmp6hdr_old)) < 0)
		return DROP_INVALID;

	/* fill icmp6hdr */
	icmp6hdr.icmp6_type = 136;
	icmp6hdr.icmp6_code = 0;
	icmp6hdr.icmp6_cksum = icmp6hdr_old.icmp6_cksum;
	icmp6hdr.icmp6_dataun.un_data32[0] = 0;

	if (to_router) {
		icmp6hdr.icmp6_router = 1;
		icmp6hdr.icmp6_solicited = 1;
		icmp6hdr.icmp6_override = 0;
	} else {
		icmp6hdr.icmp6_router = 0;
		icmp6hdr.icmp6_solicited = 1;
		icmp6hdr.icmp6_override = 1;
	}

	if (ctx_store_bytes(ctx, nh_off + sizeof(struct ipv6hdr), &icmp6hdr,
			    sizeof(icmp6hdr), 0) < 0)
		return DROP_WRITE_ERROR;

	/* fixup checksums */
	sum = csum_diff(&icmp6hdr_old, sizeof(icmp6hdr_old),
			&icmp6hdr, sizeof(icmp6hdr), 0);
	if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	/* get old options */
	if (ctx_load_bytes(ctx, nh_off + ICMP6_ND_OPTS, opts_old, sizeof(opts_old)) < 0)
		return DROP_INVALID;

	opts[0] = 2;
	opts[1] = 1;
	opts[2] = mac->addr[0];
	opts[3] = mac->addr[1];
	opts[4] = mac->addr[2];
	opts[5] = mac->addr[3];
	opts[6] = mac->addr[4];
	opts[7] = mac->addr[5];

	/* store ND_OPT_TARGET_LL_ADDR option */
	if (ctx_store_bytes(ctx, nh_off + ICMP6_ND_OPTS, opts, sizeof(opts), 0) < 0)
		return DROP_WRITE_ERROR;

	/* fixup checksum */
	sum = csum_diff(opts_old, sizeof(opts_old), opts, sizeof(opts), 0);
	if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return icmp6_send_reply(ctx, nh_off);
}

static __always_inline __be32 compute_icmp6_csum(char data[80], __u16 payload_len,
						 struct ipv6hdr *ipv6hdr)
{
	__be32 sum;

	/* compute checksum with new payload length */
	sum = csum_diff(NULL, 0, data, payload_len, 0);
	sum = ipv6_pseudohdr_checksum(ipv6hdr, IPPROTO_ICMPV6, payload_len,
				      sum);
	return sum;
}

#ifdef HAVE_CHANGE_TAIL
static __always_inline int __icmp6_send_time_exceeded(struct __ctx_buff *ctx,
						      int nh_off)
{
	/* FIXME: Fix code below to not require this init */
	char data[80] = {};
	struct icmp6hdr *icmp6hoplim;
	struct ipv6hdr *ipv6hdr;
	char *upper; /* icmp6 or tcp or udp */
	const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	__be32 sum = 0;
	__u16 payload_len = 0; /* FIXME: Uninit of this causes verifier bug */
	__u8 icmp6_nexthdr = IPPROTO_ICMPV6;
	int trimlen;

	/* initialize pointers to offsets in data */
	icmp6hoplim = (struct icmp6hdr *)data;
	ipv6hdr = (struct ipv6hdr *)(data + 8);
	upper = (data + 48);

	/* fill icmp6hdr */
	icmp6hoplim->icmp6_type = 3;
	icmp6hoplim->icmp6_code = 0;
	icmp6hoplim->icmp6_cksum = 0;
	icmp6hoplim->icmp6_dataun.un_data32[0] = 0;

	cilium_dbg(ctx, DBG_ICMP6_TIME_EXCEEDED, 0, 0);

	/* read original v6 hdr into offset 8 */
	if (ctx_load_bytes(ctx, nh_off, ipv6hdr, sizeof(*ipv6hdr)) < 0)
		return DROP_INVALID;

	if (ipv6_store_nexthdr(ctx, &icmp6_nexthdr, nh_off) < 0)
		return DROP_WRITE_ERROR;

	/* read original v6 payload into offset 48 */
	switch (ipv6hdr->nexthdr) {
	case IPPROTO_ICMPV6:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
	case IPPROTO_UDP:
		if (ctx_load_bytes(ctx, nh_off + sizeof(struct ipv6hdr),
				   upper, 8) < 0)
			return DROP_INVALID;
		sum = compute_icmp6_csum(data, 56, ipv6hdr);
		payload_len = bpf_htons(56);
		trimlen = 56 - bpf_ntohs(ipv6hdr->payload_len);
		if (ctx_change_tail(ctx, ctx_full_len(ctx) + trimlen, 0) < 0)
			return DROP_WRITE_ERROR;
		/* trim or expand buffer and copy data buffer after ipv6 header */
		if (ctx_store_bytes(ctx, nh_off + sizeof(struct ipv6hdr),
				    data, 56, 0) < 0)
			return DROP_WRITE_ERROR;
		if (ipv6_store_paylen(ctx, nh_off, &payload_len) < 0)
			return DROP_WRITE_ERROR;

		break;
		/* copy header without options */
	case IPPROTO_TCP:
		if (ctx_load_bytes(ctx, nh_off + sizeof(struct ipv6hdr),
				   upper, 20) < 0)
			return DROP_INVALID;
		sum = compute_icmp6_csum(data, 68, ipv6hdr);
		payload_len = bpf_htons(68);
		/* trim or expand buffer and copy data buffer after ipv6 header */
		trimlen = 68 - bpf_ntohs(ipv6hdr->payload_len);
		if (ctx_change_tail(ctx, ctx_full_len(ctx) + trimlen, 0) < 0)
			return DROP_WRITE_ERROR;
		if (ctx_store_bytes(ctx, nh_off + sizeof(struct ipv6hdr),
				    data, 68, 0) < 0)
			return DROP_WRITE_ERROR;
		if (ipv6_store_paylen(ctx, nh_off, &payload_len) < 0)
			return DROP_WRITE_ERROR;

		break;
	default:
		return DROP_UNKNOWN_L4;
	}

	if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return icmp6_send_reply(ctx, nh_off);
}
#endif

#ifndef SKIP_ICMPV6_HOPLIMIT_HANDLING
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED)
int tail_icmp6_send_time_exceeded(struct __ctx_buff *ctx __maybe_unused)
{
# ifdef HAVE_CHANGE_TAIL
	int ret, nh_off = ctx_load_meta(ctx, 0);
	enum metric_dir direction  = (enum metric_dir)ctx_load_meta(ctx, 1);

	ctx_store_meta(ctx, 0, 0);
	ret = __icmp6_send_time_exceeded(ctx, nh_off);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
					      direction);
	return ret;
# else
	return 0;
# endif
}
#endif

/*
 * icmp6_send_time_exceeded
 * @ctx:	socket buffer
 * @nh_off:	offset to the IPv6 header
 * @direction:  direction of packet (can be ingress or egress)
 * Send a ICMPv6 time exceeded in response to an IPv6 frame.
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
static __always_inline int icmp6_send_time_exceeded(struct __ctx_buff *ctx,
						    int nh_off, enum metric_dir direction)
{
	ctx_store_meta(ctx, 0, nh_off);
	ctx_store_meta(ctx, 1, direction);

	ep_tail_call(ctx, CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED);

	return DROP_MISSED_TAIL_CALL;
}

static __always_inline int __icmp6_handle_ns(struct __ctx_buff *ctx, int nh_off)
{
	union v6addr target, router;
	struct endpoint_info *ep;

	if (ctx_load_bytes(ctx, nh_off + ICMP6_ND_TARGET_OFFSET, target.addr,
			   sizeof(((struct ipv6hdr *)NULL)->saddr)) < 0)
		return DROP_INVALID;

	cilium_dbg(ctx, DBG_ICMP6_NS, target.p3, target.p4);

	BPF_V6(router, ROUTER_IP);

	if (ipv6_addrcmp(&target, &router) == 0) {
		union macaddr router_mac = NODE_MAC;

		return send_icmp6_ndisc_adv(ctx, nh_off, &router_mac, true);
	}

	ep = __lookup_ip6_endpoint(&target);
	if (ep) {
		union macaddr router_mac = NODE_MAC;

		return send_icmp6_ndisc_adv(ctx, nh_off, &router_mac, false);
	}

	/* Unknown target address, drop */
	return ACTION_UNKNOWN_ICMP6_NS;
}

#ifndef SKIP_ICMPV6_NS_HANDLING
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_HANDLE_ICMP6_NS)
int tail_icmp6_handle_ns(struct __ctx_buff *ctx)
{
	int ret, nh_off = ctx_load_meta(ctx, 0);
	enum metric_dir direction  = (enum metric_dir)ctx_load_meta(ctx, 1);

	ctx_store_meta(ctx, 0, 0);
	ret = __icmp6_handle_ns(ctx, nh_off);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, direction);
	return ret;
}
#endif

/*
 * icmp6_handle_ns
 * @ctx:	socket buffer
 * @nh_off:	offset to the IPv6 header
 * @direction:  direction of packet(ingress or egress)
 *
 * Respond to ICMPv6 Neighbour Solicitation
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
static __always_inline int icmp6_handle_ns(struct __ctx_buff *ctx, int nh_off,
					   enum metric_dir direction)
{
	ctx_store_meta(ctx, 0, nh_off);
	ctx_store_meta(ctx, 1, direction);

	ep_tail_call(ctx, CILIUM_CALL_HANDLE_ICMP6_NS);

	return DROP_MISSED_TAIL_CALL;
}

static __always_inline bool
is_icmp6_ndp(struct __ctx_buff *ctx, const struct ipv6hdr *ip6, int nh_off)
{
	__u8 type = icmp6_load_type(ctx, nh_off);

	return ip6->nexthdr == IPPROTO_ICMPV6 &&
	       (type == ICMP6_NS_MSG_TYPE || type == ICMP6_NA_MSG_TYPE);
}

static __always_inline int icmp6_ndp_handle(struct __ctx_buff *ctx, int nh_off,
					    enum metric_dir direction)
{
	__u8 type = icmp6_load_type(ctx, nh_off);
	cilium_dbg(ctx, DBG_ICMP6_HANDLE, type, 0);

	if (type == ICMP6_NS_MSG_TYPE)
		return icmp6_handle_ns(ctx, nh_off, direction);

	/* All branching above will have issued a tail call, all
	 * remaining traffic is subject to forwarding to containers.
	 */
	return 0;
}

static __always_inline int
icmp6_host_handle(struct __ctx_buff *ctx __maybe_unused)
{
	__u8 type __maybe_unused;

	type = icmp6_load_type(ctx, ETH_HLEN);

	/* When the host firewall is enabled, we drop and allow ICMPv6 messages
	 * according to RFC4890, except for echo request and reply messages which
	 * are handled by host policies and can be dropped.
	 * |          ICMPv6 Message         |     Action      | Type |
	 * |---------------------------------|-----------------|------|
	 * |          ICMPv6-unreach         |   CTX_ACT_OK    |   1  |
	 * |          ICMPv6-too-big         |   CTX_ACT_OK    |   2  |
	 * |           ICMPv6-timed          |   CTX_ACT_OK    |   3  |
	 * |         ICMPv6-parameter        |   CTX_ACT_OK    |   4  |
	 * |    ICMPv6-err-private-exp-100   |  CTX_ACT_DROP   |  100 |
	 * |    ICMPv6-err-private-exp-101   |  CTX_ACT_DROP   |  101 |
	 * |       ICMPv6-err-expansion      |  CTX_ACT_DROP   |  127 |
	 * |       ICMPv6-echo-message       |    Firewall     |  128 |
	 * |        ICMPv6-echo-reply        |    Firewall     |  129 |
	 * |      ICMPv6-mult-list-query     |   CTX_ACT_OK    |  130 |
	 * |      ICMPv6-mult-list-report    |   CTX_ACT_OK    |  131 |
	 * |      ICMPv6-mult-list-done      |   CTX_ACT_OK    |  132 |
	 * |      ICMPv6-router-solici       |   CTX_ACT_OK    |  133 |
	 * |      ICMPv6-router-advert       |   CTX_ACT_OK    |  134 |
	 * |     ICMPv6-neighbor-solicit     |   CTX_ACT_OK    |  135 |
	 * |      ICMPv6-neighbor-advert     |   CTX_ACT_OK    |  136 |
	 * |     ICMPv6-redirect-message     |  CTX_ACT_DROP   |  137 |
	 * |      ICMPv6-router-renumber     |   CTX_ACT_OK    |  138 |
	 * |      ICMPv6-node-info-query     |  CTX_ACT_DROP   |  139 |
	 * |     ICMPv6-node-info-response   |  CTX_ACT_DROP   |  140 |
	 * |   ICMPv6-inv-neighbor-solicit   |   CTX_ACT_OK    |  141 |
	 * |    ICMPv6-inv-neighbor-advert   |   CTX_ACT_OK    |  142 |
	 * |    ICMPv6-mult-list-report-v2   |   CTX_ACT_OK    |  143 |
	 * | ICMPv6-home-agent-disco-request |  CTX_ACT_DROP   |  144 |
	 * |  ICMPv6-home-agent-disco-reply  |  CTX_ACT_DROP   |  145 |
	 * |      ICMPv6-mobile-solicit      |  CTX_ACT_DROP   |  146 |
	 * |      ICMPv6-mobile-advert       |  CTX_ACT_DROP   |  147 |
	 * |      ICMPv6-send-solicit        |   CTX_ACT_OK    |  148 |
	 * |       ICMPv6-send-advert        |   CTX_ACT_OK    |  149 |
	 * |       ICMPv6-mobile-exp         |  CTX_ACT_DROP   |  150 |
	 * |    ICMPv6-mult-router-advert    |   CTX_ACT_OK    |  151 |
	 * |    ICMPv6-mult-router-solicit   |   CTX_ACT_OK    |  152 |
	 * |     ICMPv6-mult-router-term     |   CTX_ACT_OK    |  153 |
	 * |         ICMPv6-FMIPv6           |  CTX_ACT_DROP   |  154 |
	 * |       ICMPv6-rpl-control        |  CTX_ACT_DROP   |  155 |
	 * |   ICMPv6-info-private-exp-200   |  CTX_ACT_DROP   |  200 |
	 * |   ICMPv6-info-private-exp-201   |  CTX_ACT_DROP   |  201 |
	 * |      ICMPv6-info-expansion      |  CTX_ACT_DROP   |  255 |
	 * |       ICMPv6-unallocated        |  CTX_ACT_DROP   |      |
	 * |       ICMPv6-unassigned         |  CTX_ACT_DROP   |      |
	 */

	if (type == ICMP6_NS_MSG_TYPE)
		return CTX_ACT_OK;

	if (type == ICMP6_ECHO_REQUEST_MSG_TYPE || type == ICMP6_ECHO_REPLY_MSG_TYPE)
		/* Decision is deferred to the host policies. */
		return CTX_ACT_OK;

	if ((ICMP6_UNREACH_MSG_TYPE <= type && type <= ICMP6_PARAM_ERR_MSG_TYPE) ||
		(ICMP6_MULT_LIST_QUERY_TYPE <= type && type <= ICMP6_NA_MSG_TYPE) ||
		(ICMP6_INV_NS_MSG_TYPE <= type && type <= ICMP6_MULT_LIST_REPORT_V2_TYPE) ||
		(ICMP6_SEND_NS_MSG_TYPE <= type && type <= ICMP6_SEND_NA_MSG_TYPE) ||
		(ICMP6_MULT_RA_MSG_TYPE <= type && type <= ICMP6_MULT_RT_MSG_TYPE))
		return SKIP_HOST_FIREWALL;
	return DROP_FORBIDDEN_ICMP6;
}

#endif
