// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include <bpf/config/global.h>

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define TUNNEL_MODE		1
#define HAVE_ENCAP		1
#define ENABLE_BPF_GENEVE	1
#define ENABLE_NODEPORT		1
#define IS_BPF_OVERLAY		1
#define ENCAP_IFINDEX		42

#include "lib/common.h"
#include "lib/l4.h"
#include "lib/trace.h"

static __u32 recorded_redirect_ifindex;

static __always_inline int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused, int ifindex, __u32 flags __maybe_unused)
{
	recorded_redirect_ifindex = (__u32)ifindex;
	return CTX_ACT_REDIRECT;
}

#undef ctx_redirect
#define ctx_redirect(ctx, ifindex, flags) mock_ctx_redirect(ctx, ifindex, flags)

/* Simulated DSR conntrack state populated by bpf_overlay on SYN ingress (Stage 2)
 * and consumed by nodeport_rev_dnat_fwd_ipv4 during backend SYN-ACK egress (Stage 3).
 */
struct dsr_conn_ct_state {
	__be32 client_ip;
	__be32 backend_ip;
	__be16 client_port;
	__be16 backend_port;
	__be32 nat_vip;
	__be16 nat_port;
	__u8 valid;
	__u8 rev_dnat_applied;
};

static struct dsr_conn_ct_state test_dsr_ct;

static __always_inline int
nodeport_rev_dnat_fwd_ipv4(struct __ctx_buff *ctx, bool *snat_done,
			   bool revdnat_only __maybe_unused,
			   struct trace_ctx *trace __maybe_unused,
			   __s8 *ext_err __maybe_unused)
{
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct iphdr *ip4;
	struct tcphdr *tcp;

	if (!test_dsr_ct.valid)
		return CTX_ACT_OK;

	if (data + ETH_HLEN + sizeof(*ip4) + sizeof(*tcp) > data_end)
		return CTX_ACT_OK;

	ip4 = (struct iphdr *)((void *)data + ETH_HLEN);
	tcp = (struct tcphdr *)(ip4 + 1);

	if (ip4->protocol == IPPROTO_TCP &&
	    ip4->saddr == test_dsr_ct.backend_ip &&
	    ip4->daddr == test_dsr_ct.client_ip &&
	    tcp->source == test_dsr_ct.backend_port &&
	    tcp->dest == test_dsr_ct.client_port) {
		__be32 new_saddr = test_dsr_ct.nat_vip;
		__be16 new_sport = test_dsr_ct.nat_port;

		if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr),
				    &new_saddr, sizeof(new_saddr), 0) < 0 ||
		    ctx_store_bytes(ctx, ETH_HLEN + sizeof(*ip4) + offsetof(struct tcphdr, source),
				    &new_sport, sizeof(new_sport), 0) < 0)
			return DROP_WRITE_ERROR;

		*snat_done = true;
		test_dsr_ct.rev_dnat_applied = 1;
	}

	return CTX_ACT_OK;
}

static __always_inline int
nodeport_rev_dnat_fwd_ipv6(struct __ctx_buff *ctx __maybe_unused,
			   bool *snat_done __maybe_unused,
			   bool revdnat_only __maybe_unused,
			   struct trace_ctx *trace __maybe_unused,
			   __s8 *ext_err __maybe_unused)
{
	return CTX_ACT_OK;
}

#include "lib/geneve_encap.h"

#define __declare_overlay_tail_str(index) \
	__section(PROG_TYPE "/tail") \
	__attribute__((btf_decl_tag("tail:cilium_calls_bpf_overlay/" __stringify(index))))
#define __declare_overlay_tail(index) __declare_overlay_tail_str(index)

ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr})
ASSIGN_CONFIG(union v6addr, router_ipv6, {.addr = v6_node_one_addr})

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define TUNNEL_SRC	v4_node_one
#define TUNNEL_DST	v4_node_two
#define TUNNEL_SRC6	v6_node_one_addr
#define TUNNEL_DST6	v6_node_two_addr
#define TEST_VNI	0x00554433
#define BACKEND_VNI	0x00667788
#define DSR_VIP_IP	0x0A6000C8 /* 10.96.0.200 */
#define DSR_VIP_PORT	8443

static __u32 overlay_invoked_count;
static __u32 overlay_observed_src_label;
static __u32 overlay_observed_mark;
static struct geneve_dsr_opt4 overlay_observed_dsr;
static int overlay_observed_dsr_ret;
static __be32 overlay_observed_inner_saddr;
static __be32 overlay_observed_inner_daddr;
static __be16 overlay_observed_inner_sport;
static __be16 overlay_observed_inner_dport;
static __u8 overlay_observed_tcp_syn;
static __u8 overlay_observed_tcp_ack;
static int overlay_observed_eth_mac_ok;
static __be16 e2e_observed_wire_proto;

/* Multi-stage walkthrough state for Test 4 (full tunnel connection walkthrough) */
static __u32 full_conn_stage;
static __u32 full_conn_stage1_ifindex;
static __u32 full_conn_stage3_ifindex;
static __u16 full_conn_stage1_udp_sport;
static __u16 full_conn_stage3_udp_sport;

/* Target program in cilium_calls_bpf_overlay[CILIUM_CALL_IPV4_FROM_OVERLAY]
 * Simulates bpf_overlay's handle_ipv4 / tail_handle_ipv4 (IS_BPF_OVERLAY=1)
 * receiving the decapsulated inner packet after cross-program tail call from bpf_host.
 */
__declare_overlay_tail(CILIUM_CALL_IPV4_FROM_OVERLAY)
int mock_bpf_overlay_handle_ipv4(struct __ctx_buff *ctx)
{
	struct geneve_dsr_opt4 local_dsr = {};
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	struct ethhdr *eth;
	struct iphdr *inner_ip4;
	struct tcphdr *inner_tcp;

	overlay_invoked_count++;
	overlay_observed_src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
	overlay_observed_mark = ctx->mark;

	/* Extract Geneve DSR option via overloaded ctx_get_tunnel_opt across program boundary */
	overlay_observed_dsr_ret = ctx_get_tunnel_opt(ctx, &local_dsr, sizeof(local_dsr));
	overlay_observed_dsr = local_dsr;

	if (data + ETH_HLEN + sizeof(*inner_ip4) <= data_end) {
		eth = data;
		if (memcmp(eth->h_source, (const void *)SRC_MAC, ETH_ALEN) == 0 &&
		    memcmp(eth->h_dest, (const void *)DST_MAC, ETH_ALEN) == 0)
			overlay_observed_eth_mac_ok = 1;

		inner_ip4 = (struct iphdr *)((void *)data + ETH_HLEN);
		overlay_observed_inner_saddr = inner_ip4->saddr;
		overlay_observed_inner_daddr = inner_ip4->daddr;

		if ((void *)(inner_ip4 + 1) + sizeof(*inner_tcp) <= data_end) {
			inner_tcp = (struct tcphdr *)(inner_ip4 + 1);
			overlay_observed_inner_sport = inner_tcp->source;
			overlay_observed_inner_dport = inner_tcp->dest;
			overlay_observed_tcp_syn = inner_tcp->syn;
			overlay_observed_tcp_ack = inner_tcp->ack;
		}
	}

	/* In Test 4 (full tunnel connection walkthrough), Stage 2 (Node 2 ingress
	 * overlay delivery of client TCP SYN) records the DSR Conntrack entry,
	 * constructs the Backend Pod's TCP SYN-ACK reply (Stage 3), encapsulates
	 * it via tail_geneve_encap4 (which applies bpf_geneve_rev_dnat_fwd), and
	 * delivers the return tunnel packet into Node 1's tail_geneve_decap4 (Stage 4).
	 */
	if (full_conn_stage == 2) {
		struct bpf_geneve_metadata *egr_meta;
		struct geneve_encaphdr4 reply_hdr;
		__be32 reply_saddr = DST_IP;
		__be32 reply_daddr = SRC_IP;
		__be16 reply_sport = tcp_svc_one;
		__be16 reply_dport = tcp_src_one;
		__u8 syn_ack_flags = 0x12; /* SYN (0x02) | ACK (0x10) */
		__s8 ext_err = 0;
		int ret;

		if (overlay_observed_dsr_ret != sizeof(struct geneve_dsr_opt4))
			return DROP_INVALID;

		/* Populate DSR Conntrack state learned from Geneve DSR option */
		test_dsr_ct.client_ip = overlay_observed_inner_saddr;
		test_dsr_ct.backend_ip = overlay_observed_inner_daddr;
		test_dsr_ct.client_port = overlay_observed_inner_sport;
		test_dsr_ct.backend_port = overlay_observed_inner_dport;
		test_dsr_ct.nat_vip = local_dsr.addr;
		test_dsr_ct.nat_port = local_dsr.port;
		test_dsr_ct.valid = 1;

		/* Stage 3: Turn packet around as Backend Pod TCP SYN-ACK reply
		 * (DST_IP:tcp_svc_one -> SRC_IP:tcp_src_one, syn=1, ack=1)
		 */
		full_conn_stage = 3;
		if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr),
				    &reply_saddr, sizeof(reply_saddr), 0) < 0 ||
		    ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr),
				    &reply_daddr, sizeof(reply_daddr), 0) < 0 ||
		    ctx_store_bytes(ctx, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source),
				    &reply_sport, sizeof(reply_sport), 0) < 0 ||
		    ctx_store_bytes(ctx, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest),
				    &reply_dport, sizeof(reply_dport), 0) < 0 ||
		    ctx_store_bytes(ctx, ETH_HLEN + sizeof(struct iphdr) + 13,
				    &syn_ack_flags, sizeof(syn_ack_flags), 0) < 0)
			return DROP_WRITE_ERROR;

		egr_meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
		if (!egr_meta)
			return DROP_INVALID;
		egr_meta->magic = BPF_GENEVE_META_MAGIC;
		egr_meta->vni = BACKEND_VNI;
		egr_meta->inner_proto = bpf_htons(ETH_P_IP);
		egr_meta->opt_len = 0;
		egr_meta->ip4.daddr = TUNNEL_SRC;

		recorded_redirect_ifindex = 0;
		ret = tail_geneve_encap4(ctx);
		if (ret != CTX_ACT_REDIRECT)
			return ret;
		full_conn_stage3_ifindex = recorded_redirect_ifindex;

		if (ctx_load_bytes(ctx, ETH_HLEN, &reply_hdr, sizeof(reply_hdr)) < 0)
			return DROP_INVALID;
		full_conn_stage3_udp_sport = bpf_ntohs(reply_hdr.udp.source);

		/* Stage 4: Client Node 1 bpf_host ingress decap -> bpf_overlay */
		full_conn_stage = 4;
		return tail_call_internal(ctx, CILIUM_CALL_GENEVE_DECAP4, &ext_err);
	}

	return CTX_ACT_OK;
}

/* Test 1: End-to-End IPv4 Underlay (Default ETH_P_TEB Mode):
 * bpf_host (UDP 6081 ingress dispatch) -> tail_geneve_decap4 ->
 * cilium_calls_bpf_overlay[CILIUM_CALL_IPV4_FROM_OVERLAY] -> bpf_overlay handler
 */
PKTGEN("tc", "geneve_e2e_host_to_overlay_v4")
int bpf_geneve_e2e_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
					  SRC_IP, DST_IP,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "geneve_e2e_host_to_overlay_v4")
int bpf_geneve_e2e_v4_setup(struct __ctx_buff *ctx)
{
	struct geneve_dsr_opt4 dsr_opt = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = 2,
		},
		.addr = bpf_htonl(DSR_VIP_IP),
		.port = bpf_htons(DSR_VIP_PORT),
	};
	void *data, *data_end;
	struct geneve_encaphdr4 *hdr;
	struct iphdr *ip4;
	__be16 dport = 0;
	__s8 ext_err = 0;
	int ret;

	full_conn_stage = 0;
	test_dsr_ct.valid = 0;
	overlay_invoked_count = 0;
	overlay_observed_src_label = 0;
	overlay_observed_mark = 0;
	overlay_observed_dsr_ret = 0;
	overlay_observed_inner_saddr = 0;
	overlay_observed_inner_daddr = 0;
	overlay_observed_eth_mac_ok = 0;
	e2e_observed_wire_proto = 0;

	/* Encapsulate inner packet with IPv4 Geneve + DSR option (defaults to ETH_P_TEB mode) */
	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IP), &dsr_opt, sizeof(dsr_opt));
	if (ret < 0)
		return ret;

	/* Replicate bpf_host.c cil_from_netdev UDP ingress interception */
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(*hdr) > data_end)
		return DROP_INVALID;

	hdr = (struct geneve_encaphdr4 *)((void *)data + ETH_HLEN);
	e2e_observed_wire_proto = hdr->geneve.protocol_type;

	ip4 = &hdr->ip;
	if (ip4->protocol == IPPROTO_UDP &&
	    l4_load_port(ctx, ETH_HLEN + ipv4_hdrlen(ip4) + UDP_DPORT_OFF, &dport) == 0 &&
	    dport == bpf_htons(bpf_geneve_dport())) {
		return tail_call_internal(ctx, CILIUM_CALL_GENEVE_DECAP4, &ext_err);
	}

	return -999;
}

CHECK("tc", "geneve_e2e_host_to_overlay_v4")
int bpf_geneve_e2e_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_fatal("expected CTX_ACT_OK (%d), got %d", CTX_ACT_OK, *status_code);

	if (e2e_observed_wire_proto != bpf_htons(ETH_P_TEB))
		test_fatal("expected wire protocol ETH_P_TEB (0x%x), got 0x%x",
			   ETH_P_TEB, bpf_ntohs(e2e_observed_wire_proto));

	if (overlay_invoked_count != 1)
		test_fatal("expected bpf_overlay handler invoked once, got %u",
			   overlay_invoked_count);

	if (overlay_observed_src_label != TEST_VNI)
		test_fatal("expected src_label 0x%x, got 0x%x",
			   TEST_VNI, overlay_observed_src_label);

	if ((overlay_observed_mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_OVERLAY)
		test_fatal("expected MARK_MAGIC_OVERLAY in ctx->mark (0x%x), got 0x%x",
			   MARK_MAGIC_OVERLAY, overlay_observed_mark);

	if (overlay_observed_dsr_ret != sizeof(struct geneve_dsr_opt4))
		test_fatal("expected DSR option len %lu, got %d",
			   sizeof(struct geneve_dsr_opt4), overlay_observed_dsr_ret);

	if (overlay_observed_dsr.addr != bpf_htonl(DSR_VIP_IP) ||
	    overlay_observed_dsr.port != bpf_htons(DSR_VIP_PORT))
		test_fatal("DSR VIP mismatch across cross-program tail call");

	if (!overlay_observed_eth_mac_ok)
		test_fatal("inner Ethernet MAC addresses not preserved across e2e TEB decap");

	if (overlay_observed_inner_saddr != SRC_IP ||
	    overlay_observed_inner_daddr != DST_IP)
		test_fatal("inner IPv4 saddr/daddr mismatch after decapsulation");

	test_finish();
}

/* Test 2: End-to-End IPv4 Underlay (L3 ETH_P_IP Wire Mode):
 * Verifies bpf_host -> tail_geneve_decap4 -> bpf_overlay when incoming wire packet
 * uses L3 inner protocol mode (ETH_P_IP without inner Ethernet header).
 */
PKTGEN("tc", "geneve_e2e_host_to_overlay_v4_l3_mode")
int bpf_geneve_e2e_v4_l3_mode_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_e2e_v4_pktgen(ctx);
}

SETUP("tc", "geneve_e2e_host_to_overlay_v4_l3_mode")
int bpf_geneve_e2e_v4_l3_mode_setup(struct __ctx_buff *ctx)
{
	struct geneve_dsr_opt4 dsr_opt = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = 2,
		},
		.addr = bpf_htonl(DSR_VIP_IP),
		.port = bpf_htons(DSR_VIP_PORT),
	};
	struct {
		struct ethhdr outer_eth;
		struct geneve_encaphdr4 hdr;
		struct geneve_dsr_opt4 opt;
	} __packed prefix;
	void *data, *data_end;
	struct iphdr *ip4;
	__be16 dport = 0;
	__s8 ext_err = 0;
	int ret;

	full_conn_stage = 0;
	test_dsr_ct.valid = 0;
	overlay_invoked_count = 0;
	overlay_observed_src_label = 0;
	overlay_observed_mark = 0;
	overlay_observed_dsr_ret = 0;
	overlay_observed_inner_saddr = 0;
	overlay_observed_inner_daddr = 0;

	/* Encapsulate inner packet with IPv4 Geneve + DSR option (TEB) */
	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IP), &dsr_opt, sizeof(dsr_opt));
	if (ret < 0)
		return ret;

	/* Convert wire packet from TEB (with 14B inner eth after DSR option) to L3 IP mode */
	if (ctx_load_bytes(ctx, 0, &prefix, sizeof(prefix)) < 0)
		return DROP_INVALID;

	if (ctx_adjust_hroom(ctx, -(__s32)ETH_HLEN, BPF_ADJ_ROOM_MAC, 0) < 0)
		return DROP_INVALID;

	prefix.hdr.geneve.protocol_type = bpf_htons(ETH_P_IP);
	prefix.hdr.udp.len = bpf_htons((__u16)(bpf_ntohs(prefix.hdr.udp.len) - ETH_HLEN));
	prefix.hdr.ip.tot_len = bpf_htons((__u16)(bpf_ntohs(prefix.hdr.ip.tot_len) - ETH_HLEN));
	prefix.hdr.ip.check = 0;
	prefix.hdr.ip.check = bpf_geneve_ipv4_csum(&prefix.hdr.ip);

	if (ctx_store_bytes(ctx, 0, &prefix, sizeof(prefix), 0) < 0)
		return DROP_INVALID;

	/* Replicate bpf_host.c cil_from_netdev UDP ingress interception */
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(*ip4) > data_end)
		return DROP_INVALID;

	ip4 = (struct iphdr *)((void *)data + ETH_HLEN);
	if (ip4->protocol == IPPROTO_UDP &&
	    l4_load_port(ctx, ETH_HLEN + ipv4_hdrlen(ip4) + UDP_DPORT_OFF, &dport) == 0 &&
	    dport == bpf_htons(bpf_geneve_dport())) {
		return tail_call_internal(ctx, CILIUM_CALL_GENEVE_DECAP4, &ext_err);
	}

	return -999;
}

CHECK("tc", "geneve_e2e_host_to_overlay_v4_l3_mode")
int bpf_geneve_e2e_v4_l3_mode_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_fatal("expected CTX_ACT_OK (%d), got %d", CTX_ACT_OK, *status_code);

	if (overlay_invoked_count != 1)
		test_fatal("expected bpf_overlay handler invoked once, got %u",
			   overlay_invoked_count);

	if (overlay_observed_src_label != TEST_VNI)
		test_fatal("expected src_label 0x%x, got 0x%x",
			   TEST_VNI, overlay_observed_src_label);

	if (overlay_observed_dsr_ret != sizeof(struct geneve_dsr_opt4))
		test_fatal("expected DSR option len %lu, got %d",
			   sizeof(struct geneve_dsr_opt4), overlay_observed_dsr_ret);

	if (overlay_observed_dsr.addr != bpf_htonl(DSR_VIP_IP) ||
	    overlay_observed_dsr.port != bpf_htons(DSR_VIP_PORT))
		test_fatal("DSR VIP mismatch across cross-program tail call in L3 wire mode");

	if (overlay_observed_inner_saddr != SRC_IP ||
	    overlay_observed_inner_daddr != DST_IP)
		test_fatal("inner IPv4 saddr/daddr mismatch after L3 wire mode decapsulation");

	test_finish();
}

/* Test 3: End-to-End IPv6 Underlay:
 * bpf_host (IPv6 UDP 6081 ingress dispatch) -> tail_geneve_decap6 ->
 * cilium_calls_bpf_overlay[CILIUM_CALL_IPV4_FROM_OVERLAY] -> bpf_overlay handler
 */
PKTGEN("tc", "geneve_e2e_host_to_overlay_v6")
int bpf_geneve_e2e_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
					  SRC_IP, DST_IP,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "geneve_e2e_host_to_overlay_v6")
int bpf_geneve_e2e_v6_setup(struct __ctx_buff *ctx)
{
	struct geneve_dsr_opt4 dsr_opt = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = 2,
		},
		.addr = bpf_htonl(DSR_VIP_IP),
		.port = bpf_htons(DSR_VIP_PORT),
	};
	union v6addr saddr6 = { .addr = TUNNEL_SRC6 };
	union v6addr daddr6 = { .addr = TUNNEL_DST6 };
	void *data, *data_end;
	struct geneve_encaphdr6 *hdr6;
	struct ipv6hdr *ip6;
	__be16 dport = 0;
	__s8 ext_err = 0;
	int ret;

	full_conn_stage = 0;
	test_dsr_ct.valid = 0;
	overlay_invoked_count = 0;
	overlay_observed_src_label = 0;
	overlay_observed_mark = 0;
	overlay_observed_dsr_ret = 0;
	overlay_observed_inner_saddr = 0;
	overlay_observed_inner_daddr = 0;
	overlay_observed_eth_mac_ok = 0;
	e2e_observed_wire_proto = 0;

	/* Encapsulate inner IPv4 packet with IPv6 Geneve + DSR option (defaults to ETH_P_TEB mode) */
	ret = bpf_geneve_encap6(ctx, &saddr6, &daddr6, TEST_VNI,
				bpf_htons(ETH_P_IP), &dsr_opt, sizeof(dsr_opt));
	if (ret < 0)
		return ret;

	/* Replicate bpf_host.c cil_from_netdev IPv6 UDP ingress interception */
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(*hdr6) > data_end)
		return DROP_INVALID;

	hdr6 = (struct geneve_encaphdr6 *)((void *)data + ETH_HLEN);
	e2e_observed_wire_proto = hdr6->geneve.protocol_type;

	ip6 = &hdr6->ip6;
	if (ip6->nexthdr == IPPROTO_UDP &&
	    l4_load_port(ctx, ETH_HLEN + sizeof(*ip6) + UDP_DPORT_OFF, &dport) == 0 &&
	    dport == bpf_htons(bpf_geneve_dport())) {
		return tail_call_internal(ctx, CILIUM_CALL_GENEVE_DECAP6, &ext_err);
	}

	return -999;
}

CHECK("tc", "geneve_e2e_host_to_overlay_v6")
int bpf_geneve_e2e_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_fatal("expected CTX_ACT_OK (%d), got %d", CTX_ACT_OK, *status_code);

	if (e2e_observed_wire_proto != bpf_htons(ETH_P_TEB))
		test_fatal("expected wire protocol ETH_P_TEB (0x%x), got 0x%x",
			   ETH_P_TEB, bpf_ntohs(e2e_observed_wire_proto));

	if (overlay_invoked_count != 1)
		test_fatal("expected bpf_overlay handler invoked once, got %u",
			   overlay_invoked_count);

	if (overlay_observed_src_label != TEST_VNI)
		test_fatal("expected src_label 0x%x, got 0x%x",
			   TEST_VNI, overlay_observed_src_label);

	if ((overlay_observed_mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_OVERLAY)
		test_fatal("expected MARK_MAGIC_OVERLAY in ctx->mark (0x%x), got 0x%x",
			   MARK_MAGIC_OVERLAY, overlay_observed_mark);

	if (overlay_observed_dsr_ret != sizeof(struct geneve_dsr_opt4))
		test_fatal("expected DSR option len %lu, got %d",
			   sizeof(struct geneve_dsr_opt4), overlay_observed_dsr_ret);

	if (overlay_observed_dsr.addr != bpf_htonl(DSR_VIP_IP) ||
	    overlay_observed_dsr.port != bpf_htons(DSR_VIP_PORT))
		test_fatal("DSR VIP mismatch across IPv6 cross-program tail call");

	if (!overlay_observed_eth_mac_ok)
		test_fatal("inner Ethernet MAC addresses not preserved across e2e IPv6 TEB decap");

	if (overlay_observed_inner_saddr != SRC_IP ||
	    overlay_observed_inner_daddr != DST_IP)
		test_fatal("inner IPv4 saddr/daddr mismatch after IPv6 decapsulation");

	test_finish();
}

/* Test 4: Full 4-Stage Tunnel-Based TCP Connection Walkthrough
 * Walks a complete bidirectional tunnel connection through the native eBPF
 * Geneve datapath:
 *   Stage 1 (Sender Node 1 Egress):
 *     Client TCP SYN (SRC_IP:tcp_src_one -> DST_IP:tcp_svc_one) + DSR option
 *     (DSR_VIP_IP:DSR_VIP_PORT) -> tail_geneve_encap4() (route cache hit on
 *     ifindex 71, 5-tuple UDP sport entropy) -> wire Geneve packet.
 *   Stage 2 (Receiver Node 2 Ingress):
 *     bpf_host UDP port check -> tail_geneve_decap4() -> cross-program tail call
 *     into cilium_calls_bpf_overlay[CILIUM_CALL_IPV4_FROM_OVERLAY] ->
 *     extracts DSR option via ctx_get_tunnel_opt() and creates DSR Conntrack state.
 *   Stage 3 (Receiver Node 2 Backend Pod SYN-ACK Reply Egress):
 *     Backend Pod sends TCP SYN-ACK (DST_IP:tcp_svc_one -> SRC_IP:tcp_src_one) ->
 *     tail_geneve_encap4() invokes bpf_geneve_rev_dnat_fwd() -> rewrites inner
 *     source to DSR_VIP_IP:DSR_VIP_PORT and encapsulates into return Geneve
 *     tunnel (TUNNEL_DST -> TUNNEL_SRC on ifindex 72).
 *   Stage 4 (Sender Node 1 Ingress):
 *     tail_geneve_decap4() -> cross-program tail call into
 *     cilium_calls_bpf_overlay[CILIUM_CALL_IPV4_FROM_OVERLAY] -> verifies the
 *     decapsulated packet is the reverse-DNATed TCP SYN-ACK from VIP:8443!
 */
PKTGEN("tc", "geneve_full_tunnel_connection_walkthrough_v4")
int bpf_geneve_full_conn_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
					  SRC_IP, DST_IP,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;
	l4->syn = 1;
	l4->ack = 0;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "geneve_full_tunnel_connection_walkthrough_v4")
int bpf_geneve_full_conn_v4_setup(struct __ctx_buff *ctx)
{
	struct geneve_dsr_opt4 dsr_opt = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = 2,
		},
		.addr = bpf_htonl(DSR_VIP_IP),
		.port = bpf_htons(DSR_VIP_PORT),
	};
	struct geneve_route_entry rt_to_node2 = {
		.dmac = { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02 },
		.smac = { 0x11, 0x22, 0x33, 0x00, 0x00, 0x01 },
		.ifindex = 71,
		.saddr = TUNNEL_SRC,
		.ts = 0,
	};
	struct geneve_route_entry rt_to_node1 = {
		.dmac = { 0x11, 0x22, 0x33, 0x00, 0x00, 0x01 },
		.smac = { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02 },
		.ifindex = 72,
		.saddr = TUNNEL_DST,
		.ts = 0,
	};
	__be32 key_node2 = TUNNEL_DST;
	__be32 key_node1 = TUNNEL_SRC;
	struct bpf_geneve_metadata *egr_meta;
	struct geneve_encaphdr4 syn_hdr;
	__be16 dport = 0;
	__s8 ext_err = 0;
	int ret;

	memset(&test_dsr_ct, 0, sizeof(test_dsr_ct));
	overlay_invoked_count = 0;
	overlay_observed_src_label = 0;
	overlay_observed_mark = 0;
	overlay_observed_dsr_ret = 0;
	overlay_observed_inner_saddr = 0;
	overlay_observed_inner_daddr = 0;
	overlay_observed_inner_sport = 0;
	overlay_observed_inner_dport = 0;
	overlay_observed_tcp_syn = 0;
	overlay_observed_tcp_ack = 0;
	full_conn_stage1_ifindex = 0;
	full_conn_stage3_ifindex = 0;
	full_conn_stage1_udp_sport = 0;
	full_conn_stage3_udp_sport = 0;

	/* Populate underlay route cache for both tunnel directions */
	map_update_elem(&cilium_geneve_routes, &key_node2, &rt_to_node2, BPF_ANY);
	map_update_elem(&cilium_geneve_routes, &key_node1, &rt_to_node1, BPF_ANY);

	/* Stage 1: Encapsulate client TCP SYN + DSR option via tail_geneve_encap4 */
	full_conn_stage = 1;
	egr_meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
	if (!egr_meta)
		return DROP_INVALID;
	egr_meta->magic = BPF_GENEVE_META_MAGIC;
	egr_meta->vni = TEST_VNI;
	egr_meta->inner_proto = bpf_htons(ETH_P_IP);
	egr_meta->ip4.daddr = TUNNEL_DST;
	egr_meta->opt_len = sizeof(dsr_opt);
	memcpy(egr_meta->raw_opts, &dsr_opt, sizeof(dsr_opt));

	recorded_redirect_ifindex = 0;
	ret = tail_geneve_encap4(ctx);
	if (ret != CTX_ACT_REDIRECT)
		return ret;
	full_conn_stage1_ifindex = recorded_redirect_ifindex;

	if (ctx_load_bytes(ctx, ETH_HLEN, &syn_hdr, sizeof(syn_hdr)) < 0)
		return DROP_INVALID;
	full_conn_stage1_udp_sport = bpf_ntohs(syn_hdr.udp.source);

	/* Stage 2: Node 2 bpf_host ingress dispatch -> tail_geneve_decap4 ->
	 * cilium_calls_bpf_overlay (which chains into Stage 3 & Stage 4).
	 */
	full_conn_stage = 2;
	if (syn_hdr.ip.protocol == IPPROTO_UDP &&
	    l4_load_port(ctx, ETH_HLEN + sizeof(struct iphdr) + UDP_DPORT_OFF, &dport) == 0 &&
	    dport == bpf_htons(bpf_geneve_dport())) {
		return tail_call_internal(ctx, CILIUM_CALL_GENEVE_DECAP4, &ext_err);
	}

	return -999;
}

CHECK("tc", "geneve_full_tunnel_connection_walkthrough_v4")
int bpf_geneve_full_conn_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_fatal("expected CTX_ACT_OK (%d), got %d", CTX_ACT_OK, *status_code);

	if (full_conn_stage != 4)
		test_fatal("expected full connection walkthrough to complete Stage 4, stopped at %u",
			   full_conn_stage);

	/* Verify Stage 1 (forward SYN encap) and Stage 3 (reply SYN-ACK encap) route cache & sport */
	if (full_conn_stage1_ifindex != 71 || full_conn_stage3_ifindex != 72)
		test_fatal("unexpected tunnel redirect ifindexes: stage1=%u, stage3=%u",
			   full_conn_stage1_ifindex, full_conn_stage3_ifindex);

	if (full_conn_stage1_udp_sport < 32768 || full_conn_stage3_udp_sport < 32768)
		test_fatal("tunnel UDP source ports not in ephemeral range: %u, %u",
			   full_conn_stage1_udp_sport, full_conn_stage3_udp_sport);

	/* Verify bpf_overlay was invoked twice (Stage 2 SYN ingress + Stage 4 SYN-ACK ingress) */
	if (overlay_invoked_count != 2)
		test_fatal("expected bpf_overlay invoked twice (SYN + SYN-ACK), got %u",
			   overlay_invoked_count);

	/* Verify Conntrack creation in Stage 2 and Reverse DNAT execution in Stage 3 */
	if (!test_dsr_ct.valid || !test_dsr_ct.rev_dnat_applied)
		test_fatal("expected DSR conntrack creation and reverse DNAT on reply");

	/* Verify final packet delivered at Stage 4 is the reverse-DNATed TCP SYN-ACK from VIP:8443 */
	if (overlay_observed_src_label != BACKEND_VNI)
		test_fatal("expected return tunnel VNI 0x%x, got 0x%x",
			   BACKEND_VNI, overlay_observed_src_label);

	if (overlay_observed_inner_saddr != bpf_htonl(DSR_VIP_IP) ||
	    overlay_observed_inner_daddr != SRC_IP)
		test_fatal("expected reverse-DNATed saddr=0x%x, daddr=0x%x, got 0x%x -> 0x%x",
			   bpf_htonl(DSR_VIP_IP), SRC_IP,
			   overlay_observed_inner_saddr, overlay_observed_inner_daddr);

	if (overlay_observed_inner_sport != bpf_htons(DSR_VIP_PORT) ||
	    overlay_observed_inner_dport != tcp_src_one)
		test_fatal("expected reverse-DNATed sport=%u, dport=%u, got %u -> %u",
			   DSR_VIP_PORT, bpf_ntohs(tcp_src_one),
			   bpf_ntohs(overlay_observed_inner_sport),
			   bpf_ntohs(overlay_observed_inner_dport));

	if (overlay_observed_tcp_syn != 1 || overlay_observed_tcp_ack != 1)
		test_fatal("expected final delivered TCP flags SYN=1 ACK=1, got SYN=%u ACK=%u",
			   overlay_observed_tcp_syn, overlay_observed_tcp_ack);

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");

