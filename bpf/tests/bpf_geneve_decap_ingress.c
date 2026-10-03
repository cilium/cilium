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
#define ENCAP_IFINDEX		42

#include "lib/common.h"
#include "lib/tailcall.h"

static volatile __u16 test_tunnel_port = 6081;

#undef CONFIG
#define __REAL_CONFIG(name)	\
(*({				\
	void *out;		\
	asm volatile("%0 = " __stringify(__config_##name) " ll"	\
			: "=r"(out));	\
	(typeof(__config_##name) *)out;	\
}))
#define CONFIG(name) \
	__builtin_choose_expr(__builtin_strcmp(#name, "tunnel_port") == 0, \
			      test_tunnel_port, \
			      __REAL_CONFIG(name))

static __u32 intercepted_slot;
static __u32 intercepted_mark;
static __u32 intercepted_src_label;

#include "lib/geneve_encap.h"

#define __declare_overlay_tail_str(index) \
	__section(PROG_TYPE "/tail") \
	__attribute__((btf_decl_tag("tail:cilium_calls_bpf_overlay/" __stringify(index))))
#define __declare_overlay_tail(index) __declare_overlay_tail_str(index)

__declare_overlay_tail(CILIUM_CALL_IPV4_FROM_OVERLAY)
int mock_overlay_tailcall_v4(struct __ctx_buff *ctx)
{
	intercepted_slot = CILIUM_CALL_IPV4_FROM_OVERLAY;
	intercepted_mark = ctx->mark;
	intercepted_src_label = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	return 0;
}

__declare_overlay_tail(CILIUM_CALL_IPV6_FROM_OVERLAY)
int mock_overlay_tailcall_v6(struct __ctx_buff *ctx)
{
	intercepted_slot = CILIUM_CALL_IPV6_FROM_OVERLAY;
	intercepted_mark = ctx->mark;
	intercepted_src_label = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	return 0;
}

ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr})
ASSIGN_CONFIG(union v6addr, router_ipv6, {.addr = v6_node_one_addr})

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define TUNNEL_SRC_V4	v4_node_one
#define TUNNEL_DST_V4	v4_node_two
#define TEST_SECLABEL	0x112233

#define INNER_LEN	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static const union v6addr tunnel_saddr_v6 = { .addr = v6_node_one_addr };
static const union v6addr tunnel_daddr_v6 = { .addr = v6_node_two_addr };
static __be16 observed_wire_proto_v4;
static __be16 observed_wire_proto_v6;

PKTGEN("tc", "geneve_decap_ingress_v4")
int bpf_geneve_decap_ingress_v4_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_decap_ingress_v4")
int bpf_geneve_decap_ingress_v4_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct geneve_encaphdr4 *hdr;
	int ret;

	observed_wire_proto_v4 = 0;

	/* Encapsulate packet with native BPF Geneve IPv4 (defaults to ETH_P_TEB mode) */
	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_SECLABEL,
				bpf_htons(ETH_P_IP), NULL, 0);
	if (ret < 0)
		return ret;

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(*hdr) <= data_end) {
		hdr = (struct geneve_encaphdr4 *)((void *)data + ETH_HLEN);
		observed_wire_proto_v4 = hdr->geneve.protocol_type;
	}

	/* Run native BPF Geneve ingress decapsulation */
	return tail_geneve_decap4(ctx);
}

CHECK("tc", "geneve_decap_ingress_v4")
int bpf_geneve_decap_ingress_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != 0)
		test_fatal("tail_geneve_decap4 returned error: %d", *status_code);

	if (observed_wire_proto_v4 != bpf_htons(ETH_P_TEB))
		test_fatal("expected wire protocol ETH_P_TEB (0x%x), got 0x%x",
			   ETH_P_TEB, bpf_ntohs(observed_wire_proto_v4));

	if (intercepted_slot != CILIUM_CALL_IPV4_FROM_OVERLAY)
		test_fatal("expected tail call slot %d, got %d",
			   CILIUM_CALL_IPV4_FROM_OVERLAY, intercepted_slot);

	if ((intercepted_mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_OVERLAY)
		test_fatal("expected MARK_MAGIC_OVERLAY (0x%x), got 0x%x",
			   MARK_MAGIC_OVERLAY, intercepted_mark & MARK_MAGIC_HOST_MASK);

	if (intercepted_src_label != TEST_SECLABEL)
		test_fatal("expected CB_SRC_LABEL 0x%x, got 0x%x",
			   TEST_SECLABEL, intercepted_src_label);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("restored packet proto mismatch: 0x%x", bpf_ntohs(eth->h_proto));

	if (memcmp(eth->h_source, (const void *)SRC_MAC, ETH_ALEN) != 0 ||
	    memcmp(eth->h_dest, (const void *)DST_MAC, ETH_ALEN) != 0)
		test_fatal("restored inner Ethernet MAC mismatch after decap v4");

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");

	if (ip4->saddr != SRC_IP || ip4->daddr != DST_IP)
		test_fatal("inner IP corrupted after decap v4");

	if ((void *)eth + INNER_LEN != data_end)
		test_fatal("inner packet length changed after decap v4");

	test_finish();
}

PKTGEN("tc", "geneve_decap_ingress_v4_l3_mode")
int bpf_geneve_decap_ingress_v4_l3_mode_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_decap_ingress_v4_pktgen(ctx);
}

SETUP("tc", "geneve_decap_ingress_v4_l3_mode")
int bpf_geneve_decap_ingress_v4_l3_mode_setup(struct __ctx_buff *ctx)
{
	struct ethhdr outer_eth;
	struct geneve_encaphdr4 hdr4;
	int ret;

	/* Encapsulate packet with native BPF Geneve IPv4 (TEB) */
	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_SECLABEL,
				bpf_htons(ETH_P_IP), NULL, 0);
	if (ret < 0)
		return ret;

	/* Convert wire packet from TEB (with 14B inner eth) to L3 IP mode (ETH_P_IP, no inner eth) */
	if (ctx_load_bytes(ctx, 0, &outer_eth, sizeof(outer_eth)) < 0 ||
	    ctx_load_bytes(ctx, ETH_HLEN, &hdr4, sizeof(hdr4)) < 0)
		return DROP_INVALID;

	if (ctx_adjust_hroom(ctx, -(__s32)ETH_HLEN, BPF_ADJ_ROOM_MAC, 0) < 0)
		return DROP_INVALID;

	hdr4.geneve.protocol_type = bpf_htons(ETH_P_IP);
	hdr4.udp.len = bpf_htons((__u16)(bpf_ntohs(hdr4.udp.len) - ETH_HLEN));
	hdr4.ip.tot_len = bpf_htons((__u16)(bpf_ntohs(hdr4.ip.tot_len) - ETH_HLEN));
	hdr4.ip.check = 0;
	hdr4.ip.check = bpf_geneve_ipv4_csum(&hdr4.ip);

	if (ctx_store_bytes(ctx, 0, &outer_eth, sizeof(outer_eth), 0) < 0 ||
	    ctx_store_bytes(ctx, ETH_HLEN, &hdr4, sizeof(hdr4), 0) < 0)
		return DROP_INVALID;

	/* Run native BPF Geneve ingress decapsulation on L3-mode wire packet */
	return tail_geneve_decap4(ctx);
}

CHECK("tc", "geneve_decap_ingress_v4_l3_mode")
int bpf_geneve_decap_ingress_v4_l3_mode_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != 0)
		test_fatal("tail_geneve_decap4 (L3 wire mode) returned error: %d", *status_code);

	if (intercepted_slot != CILIUM_CALL_IPV4_FROM_OVERLAY)
		test_fatal("expected tail call slot %d, got %d",
			   CILIUM_CALL_IPV4_FROM_OVERLAY, intercepted_slot);

	if ((intercepted_mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_OVERLAY)
		test_fatal("expected MARK_MAGIC_OVERLAY (0x%x), got 0x%x",
			   MARK_MAGIC_OVERLAY, intercepted_mark & MARK_MAGIC_HOST_MASK);

	if (intercepted_src_label != TEST_SECLABEL)
		test_fatal("expected CB_SRC_LABEL 0x%x, got 0x%x",
			   TEST_SECLABEL, intercepted_src_label);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("restored packet proto mismatch: 0x%x", bpf_ntohs(eth->h_proto));

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");

	if (ip4->saddr != SRC_IP || ip4->daddr != DST_IP)
		test_fatal("inner IP corrupted after L3 mode decap v4");

	if ((void *)eth + INNER_LEN != data_end)
		test_fatal("inner packet length changed after L3 mode decap v4");

	test_finish();
}

PKTGEN("tc", "geneve_decap_ingress_v6")
int bpf_geneve_decap_ingress_v6_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_decap_ingress_v6")
int bpf_geneve_decap_ingress_v6_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct geneve_encaphdr6 *hdr6;
	int ret;

	observed_wire_proto_v6 = 0;

	/* Encapsulate packet with native BPF Geneve IPv6 (defaults to ETH_P_TEB mode) */
	ret = bpf_geneve_encap6(ctx, &tunnel_saddr_v6, &tunnel_daddr_v6, TEST_SECLABEL,
				bpf_htons(ETH_P_IP), NULL, 0);
	if (ret < 0)
		return ret;

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(*hdr6) <= data_end) {
		hdr6 = (struct geneve_encaphdr6 *)((void *)data + ETH_HLEN);
		observed_wire_proto_v6 = hdr6->geneve.protocol_type;
	}

	/* Run native BPF Geneve ingress decapsulation */
	return tail_geneve_decap6(ctx);
}

CHECK("tc", "geneve_decap_ingress_v6")
int bpf_geneve_decap_ingress_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != 0)
		test_fatal("tail_geneve_decap6 returned error: %d", *status_code);

	if (observed_wire_proto_v6 != bpf_htons(ETH_P_TEB))
		test_fatal("expected wire protocol ETH_P_TEB (0x%x), got 0x%x",
			   ETH_P_TEB, bpf_ntohs(observed_wire_proto_v6));

	if (intercepted_slot != CILIUM_CALL_IPV4_FROM_OVERLAY)
		test_fatal("expected tail call slot %d, got %d",
			   CILIUM_CALL_IPV4_FROM_OVERLAY, intercepted_slot);

	if ((intercepted_mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_OVERLAY)
		test_fatal("expected MARK_MAGIC_OVERLAY (0x%x), got 0x%x",
			   MARK_MAGIC_OVERLAY, intercepted_mark & MARK_MAGIC_HOST_MASK);

	if (intercepted_src_label != TEST_SECLABEL)
		test_fatal("expected CB_SRC_LABEL 0x%x, got 0x%x",
			   TEST_SECLABEL, intercepted_src_label);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("restored packet proto mismatch: 0x%x", bpf_ntohs(eth->h_proto));

	if (memcmp(eth->h_source, (const void *)SRC_MAC, ETH_ALEN) != 0 ||
	    memcmp(eth->h_dest, (const void *)DST_MAC, ETH_ALEN) != 0)
		test_fatal("restored inner Ethernet MAC mismatch after decap v6");

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");

	if (ip4->saddr != SRC_IP || ip4->daddr != DST_IP)
		test_fatal("inner IP corrupted after decap v6");

	if ((void *)eth + INNER_LEN != data_end)
		test_fatal("inner packet length changed after decap v6");

	test_finish();
}

/* Test 4: Custom CONFIG(tunnel_port) (e.g. 16081) Roundtrip & Mismatch Rejection
 * Verifies:
 * - bpf_geneve_encap4() uses bpf_geneve_dport() (16081) in the outer UDP header
 * - bpf_geneve_extract_dsr_v4() (via bpf_geneve_load_wire_opts) inspects wire options
 *   on custom port 16081
 * - bpf_geneve_decap4() rejects a packet when expected port (6081) does not match
 *   wire UDP dest (16081) with DROP_INVALID
 * - tail_geneve_decap4() succeeds when CONFIG(tunnel_port) == 16081
 */
static __be16 custom_port_observed_udp_dest;
static __be32 custom_port_extracted_vip;
static __be16 custom_port_extracted_port;
static bool custom_port_extracted_dsr;
static int custom_port_mismatch_ret;

PKTGEN("tc", "geneve_custom_tunnel_port_roundtrip_and_mismatch_drop")
int bpf_geneve_custom_port_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_decap_ingress_v4_pktgen(ctx);
}

SETUP("tc", "geneve_custom_tunnel_port_roundtrip_and_mismatch_drop")
int bpf_geneve_custom_port_setup(struct __ctx_buff *ctx)
{
	struct geneve_dsr_opt4 dsr_opt = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = 2,
		},
		.addr = bpf_htonl(0x0A6000FE),
		.port = bpf_htons(9443),
	};
	struct bpf_tunnel_key dummy_key = {};
	struct geneve_encaphdr4 hdr4;
	int ret;

	custom_port_observed_udp_dest = 0;
	custom_port_extracted_vip = 0;
	custom_port_extracted_port = 0;
	custom_port_extracted_dsr = false;
	custom_port_mismatch_ret = 0;
	intercepted_slot = 0;

	/* Configure custom tunnel port 16081 */
	test_tunnel_port = 16081;

	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_SECLABEL,
				bpf_htons(ETH_P_IP), &dsr_opt, sizeof(dsr_opt));
	if (ret < 0) {
		test_tunnel_port = 6081;
		return ret;
	}

	if (ctx_load_bytes(ctx, ETH_HLEN, &hdr4, sizeof(hdr4)) < 0) {
		test_tunnel_port = 6081;
		return DROP_INVALID;
	}
	custom_port_observed_udp_dest = hdr4.udp.dest;

	/* Verify in-place wire inspection on custom port 16081 */
	bpf_geneve_clear_ingress_meta();
	ret = bpf_geneve_extract_dsr_v4(ctx, &custom_port_extracted_vip,
					&custom_port_extracted_port,
					&custom_port_extracted_dsr);
	if (ret < 0) {
		test_tunnel_port = 6081;
		return ret;
	}

	/* Negative check: when expected port is 6081, decap of 16081 packet must return DROP_INVALID */
	test_tunnel_port = 6081;
	custom_port_mismatch_ret = bpf_geneve_decap4(ctx, &dummy_key);

	/* Positive check: when expected port is 16081, tail_geneve_decap4 succeeds */
	test_tunnel_port = 16081;
	ret = tail_geneve_decap4(ctx);
	test_tunnel_port = 6081;
	return ret;
}

CHECK("tc", "geneve_custom_tunnel_port_roundtrip_and_mismatch_drop")
int bpf_geneve_custom_port_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != 0)
		test_fatal("tail_geneve_decap4 on custom port 16081 failed: %d", *status_code);

	if (custom_port_observed_udp_dest != bpf_htons(16081))
		test_fatal("expected outer UDP dest 16081, got %u",
			   bpf_ntohs(custom_port_observed_udp_dest));

	if (!custom_port_extracted_dsr ||
	    custom_port_extracted_vip != bpf_htonl(0x0A6000FE) ||
	    custom_port_extracted_port != bpf_htons(9443))
		test_fatal("in-place DSR extraction on custom port 16081 failed");

	if (custom_port_mismatch_ret != DROP_INVALID)
		test_fatal("expected DROP_INVALID (%d) on mismatched port, got %d",
			   DROP_INVALID, custom_port_mismatch_ret);

	if (intercepted_slot != CILIUM_CALL_IPV4_FROM_OVERLAY)
		test_fatal("expected tail call slot %d after custom port decap, got %d",
			   CILIUM_CALL_IPV4_FROM_OVERLAY, intercepted_slot);

	test_finish();
}

