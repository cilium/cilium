/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#define ENABLE_IPV4
#define ENABLE_IPV6
#define TUNNEL_MODE
#define ENABLE_IPSEC 1
#define ENCAP_IFINDEX   1

/* For testing L2/L3 devices, we make use of ETH_HLEN:
 * IS_BPF_WIREGUARD -> 0
 * IS_BPF_HOST      -> 14 by default
 */
#if defined(IS_BPF_WIREGUARD)
# undef IS_BPF_WIREGUARD
# include "bpf_wireguard.c"
#elif defined(IS_BPF_HOST)
# undef IS_BPF_HOST
# include "bpf_host.c"
#else
# error "this file supports inclusion only from files with IS_BPF_HOST or IS_BPF_WIREGUARD defined"
#endif

#include "common.h"
#include "pktgen.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_VXLAN)

/* Assign lower values for testing, so that we don't need to craft big packet. */
ASSIGN_CONFIG(__u32, trace_payload_len, 10UL);
ASSIGN_CONFIG(__u32, trace_payload_len_overlay, 20UL);

/* Defining checks for packets from L3 devices as a macro for reusability. */
#define L3_DEVICE_CHECK(flags, is_ipv4)                                      \
{                                                                            \
	assert((((flags) & CLS_FLAG_L3_DEV) != 0) == (ETH_HLEN == 0));       \
	if (is_ipv4) {                                                       \
		assert(((flags) & CLS_FLAG_IPV6) == 0);                      \
	} else {                                                             \
		assert((((flags) & CLS_FLAG_IPV6) != 0));                    \
	}                                                                    \
}

/* Remove the L2 layer to simulate packet in an L3 device. */
static __always_inline void
adjust_l2(struct __ctx_buff *ctx)
{
	if (!THIS_IS_L3_DEV)
		return;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;

	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);
}

static __always_inline int
pktgen(struct __ctx_buff *ctx, bool is_ipv4)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	if (is_ipv4)
		l4 = pktgen__push_ipv4_udp_packet(&builder,
						  (__u8 *)mac_one,
						  (__u8 *)mac_two,
						  v4_node_one,
						  v4_node_two,
						  tcp_src_one,
						  tcp_src_two);
	else
		l4 = pktgen__push_ipv6_udp_packet(&builder,
						  (__u8 *)mac_one,
						  (__u8 *)mac_two,
						  (__u8 *)v6_node_one,
						  (__u8 *)v6_node_two,
						  tcp_src_one,
						  tcp_src_two);

	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

static __always_inline int
check(struct __ctx_buff *ctx, bool is_ipv4)
{
	test_init();

	adjust_l2(ctx);

	void *data, *data_end;
	struct iphdr *ip4;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	cls_flags_t flags;
	enum trace_point obs_point;
	__be16 proto;

	/* Parse L3/L4 once. */
	if (is_ipv4) {
		assert(revalidate_data(ctx, &data, &data_end, &ip4));
		udp = (void *)ip4 + sizeof(struct iphdr);
		assert((void *)udp + sizeof(struct udphdr) <= data_end);
		proto = bpf_htons(ETH_P_IP);
	} else {
		assert(revalidate_data(ctx, &data, &data_end, &ip6));
		udp = (void *)ip6 + sizeof(struct ipv6hdr);
		assert((void *)udp + sizeof(struct udphdr) <= data_end);
		proto = bpf_htons(ETH_P_IPV6);
	}

	/*
	 * Ensure L3_DEVICE_CHECK:
	 * - CLS_FLAG_L3_DEV is set only when ETH_HLEN is zero.
	 * - CLS_FLAG_IPv6 is set with IPv6 packets and ETH_HLEN is zero.
	 *
	 * Trace observation point here does not matter.
	 */
	TEST("native", {
		obs_point = TRACE_POINT_UNKNOWN;
		flags = ctx_classify(ctx, proto, obs_point);
		L3_DEVICE_CHECK(flags, is_ipv4);
	})

	/*
	 * Ensure CLS_FLAG_VXLAN is set with MARK_MAGIC_OVERLAY.
	 * Use TRACE_TO_{NETWORK,CRYPTO} based on IS_BPF_{HOST,WIREGUARD}.
	 */
	TEST("overlay-by-mark", {
		ctx->mark = MARK_MAGIC_OVERLAY;
		obs_point = is_defined(IS_BPF_HOST) ? TRACE_TO_NETWORK :
			    is_defined(IS_BPF_WIREGUARD) ? TRACE_TO_CRYPTO : TRACE_POINT_UNKNOWN;
		flags = ctx_classify(ctx, proto, obs_point);
		L3_DEVICE_CHECK(flags, is_ipv4);
		assert(flags & CLS_FLAG_VXLAN);
	})

	/*
	 * Ensure CLS_FLAG_VXLAN is set with UDP and tunnel_port.
	 * Use TRACE_FROM_{NETWORK,CRYPTO} based on IS_BPF_{HOST,WIREGUARD}.
	 */
	TEST("overlay-by-headers", {
		ctx->mark = 0;
		udp->dest = bpf_htons(CONFIG(tunnel_port));
		obs_point = is_defined(IS_BPF_HOST) ? TRACE_FROM_NETWORK :
			    is_defined(IS_BPF_WIREGUARD) ? TRACE_FROM_CRYPTO : TRACE_POINT_UNKNOWN;
		flags = ctx_classify(ctx, proto, obs_point);
		L3_DEVICE_CHECK(flags, is_ipv4);
		assert(flags & CLS_FLAG_VXLAN);
	})

	test_finish();
}

PKTGEN("tc", "ctx_classify4")
static __always_inline int
ctx_classify4_pktgen(struct __ctx_buff *ctx) {
	return pktgen(ctx, true);
}

CHECK("tc", "ctx_classify4")
int ctx_classify4_check(struct __ctx_buff *ctx)
{
	return check(ctx, true);
}

PKTGEN("tc", "ctx_classify6")
static __always_inline int
ctx_classify6_pktgen(struct __ctx_buff *ctx) {
	return pktgen(ctx, false);
}

CHECK("tc", "ctx_classify6")
int ctx_classify6_check(struct __ctx_buff *ctx)
{
	return check(ctx, false);
}

PKTGEN("tc", "compute_capture_len")
static __always_inline int
compute_capture_len_pktgen(struct __ctx_buff *ctx) {
	return pktgen(ctx, true);
}

CHECK("tc", "compute_capture_len")
int compute_capture_len_check(struct __ctx_buff *ctx)
{
	test_init();

	enum trace_point obs_point = TRACE_TO_OVERLAY;
	cls_flags_t flags = CLS_FLAG_NONE;
	__u64 cap_len;
	__u32 monitor;

	/*
	 * Ensure capture length equal to monitor with monitor != 0.
	 */
	TEST("monitor-nonzero", {
		monitor = 1;
		cap_len = compute_capture_len(ctx, monitor, flags, obs_point);
		assert(cap_len == monitor);
	})

	/*
	 * Ensure capture length equal to ctx_full_len with monitor > ctx_full_len.
	 */
	TEST("monitor-greater", {
		monitor = (__u32)(ctx_full_len(ctx) + 1);
		cap_len = compute_capture_len(ctx, monitor, flags, obs_point);
		assert(cap_len == ctx_full_len(ctx));
	})

	/*
	 * Ensure capture length equal to default trace_payload_len with monitor == 0.
	 */
	TEST("monitor-zero", {
		monitor = 0;
		cap_len = compute_capture_len(ctx, monitor, flags, obs_point);
		assert(cap_len == CONFIG(trace_payload_len));
	})

	/*
	 * Ensure capture length equal to default trace_payload_len with monitor == 0 and no
	 * overlay flags being set.
	 */
	TEST("monitor-non-overlay-flag", {
		monitor = 0;
		cap_len = compute_capture_len(ctx, monitor, flags, obs_point);
		assert(cap_len == CONFIG(trace_payload_len));
	})

	/*
	 * Ensure capture length equal to default trace_payload_len with monitor == 0 but invalid
	 * overlay observation point.
	 */
	TEST("monitor-non-overlay-point", {
		flags = cls_flag_tunnel();
		monitor = 0;
		cap_len = compute_capture_len(ctx, monitor, flags, obs_point);
		assert(cap_len == CONFIG(trace_payload_len));
	})

	/*
	 * Ensure capture length equal to default trace_payload_len_overlay with monitor == 0
	 * and a valid overlay observation point.
	 */
	TEST("monitor-zero-overlay", {
		obs_point = TRACE_POINT_UNKNOWN;
		flags = cls_flag_tunnel();
		monitor = 0;
		cap_len = compute_capture_len(ctx, monitor, flags, obs_point);
		assert(cap_len == CONFIG(trace_payload_len_overlay));
	})

	/*
	 * Ensure capture length equal to default trace_payload_len_overlay with
	 * monitor == TRACE_PAYLOAD_LEN and a valid overlay observation point.
	 */
	TEST("monitor-payloadlen-overlay", {
		obs_point = TRACE_POINT_UNKNOWN;
		flags = cls_flag_tunnel();
		monitor = CONFIG(trace_payload_len);
		cap_len = compute_capture_len(ctx, monitor, flags, obs_point);
		assert(cap_len == CONFIG(trace_payload_len_overlay));
	})

	test_finish();
}
