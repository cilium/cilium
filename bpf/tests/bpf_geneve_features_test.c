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

/* Mock ctx_redirect, ktime_get_ns, and fib_lookup so tail_geneve_encap4/6 can
 * deterministically test route cache hits, TTL expiration, and FIB re-learning.
 */
static __u32 recorded_redirect_ifindex;
static __u64 mock_now_ns = 100ULL * 1000000000ULL;
static bool mock_fib_lookup_enable;
static __u32 mock_fib_lookup_calls;

static __always_inline int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused, int ifindex, __u32 flags __maybe_unused)
{
	recorded_redirect_ifindex = (__u32)ifindex;
	return CTX_ACT_REDIRECT;
}

static __always_inline __u64
mock_ktime_get_ns(void)
{
	return mock_now_ns;
}

static __always_inline long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	const __u8 new_dmac[ETH_ALEN] = { 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };
	const __u8 new_smac[ETH_ALEN] = { 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

	mock_fib_lookup_calls++;
	if (!mock_fib_lookup_enable)
		return BPF_FIB_LKUP_RET_NOT_FWDED;

	memcpy(params->dmac, new_dmac, ETH_ALEN);
	memcpy(params->smac, new_smac, ETH_ALEN);
	params->ifindex = 88;
	params->ipv4_src = v4_node_one;
	return BPF_FIB_LKUP_RET_SUCCESS;
}

#undef ctx_redirect
#define ctx_redirect(ctx, ifindex, flags) mock_ctx_redirect(ctx, ifindex, flags)
#undef ktime_get_ns
#define ktime_get_ns() mock_ktime_get_ns()
#undef fib_lookup
#define fib_lookup(ctx, params, plen, flags) mock_fib_lookup(ctx, params, plen, flags)

#include "lib/geneve_encap.h"

ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr})
ASSIGN_CONFIG(union v6addr, router_ipv6, {.addr = v6_node_one_addr})

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define TUNNEL_SRC	v4_node_one
#define TUNNEL_DST	v4_node_two
#define TEST_VNI	0x778899

static struct bpf_tunnel_key max_tlv_key;

/* Test 1: Full 63-TLV / 252-Byte Maximum RFC 8926 Protocol Limit Roundtrip
 * Verifies:
 * - Power-of-two chunked copy (128 + 64 + 32 + 16 + 8 + 4 = 252 bytes) in both
 *   bpf_geneve_store_opts() and bpf_geneve_load_opts()
 * - O(1) verifier bounded loop parsing all 63 TLVs in bpf_geneve_validate_opts()
 * - Lookup of TLVs across the full 252-byte span (#1 at offset 0, #32 at offset 124,
 *   and #63 at offset 248) via bpf_geneve_find_opt()
 */
struct max_63_tlvs_payload {
	struct geneve_opt_hdr tlvs[BPF_GENEVE_OPT_MAX_COUNT];
} __packed;

PKTGEN("tc", "geneve_63_tlv_max_roundtrip")
int bpf_geneve_63_tlv_max_roundtrip_pktgen(struct __ctx_buff *ctx)
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

static __be16 max_tlv_wire_proto;

SETUP("tc", "geneve_63_tlv_max_roundtrip")
int bpf_geneve_63_tlv_max_roundtrip_setup(struct __ctx_buff *ctx)
{
	struct max_63_tlvs_payload opts = {};
	void *data, *data_end;
	struct geneve_encaphdr4 *hdr;
	int ret;

	max_tlv_wire_proto = 0;

	/* Populate 63 distinct 4-byte TLVs totaling 252 bytes (63 * 4) */
	for (int i = 0; i < BPF_GENEVE_OPT_MAX_COUNT; i++) {
		opts.tlvs[i].opt_class = bpf_htons((__u16)(0x1000 + i));
		opts.tlvs[i].type = (__u8)i;
		opts.tlvs[i].length = 0;
	}

	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IP), &opts, sizeof(opts));
	if (ret < 0)
		return ret;

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(*hdr) <= data_end) {
		hdr = (struct geneve_encaphdr4 *)((void *)data + ETH_HLEN);
		max_tlv_wire_proto = hdr->geneve.protocol_type;
	}

	return bpf_geneve_decap4(ctx, &max_tlv_key);
}

CHECK("tc", "geneve_63_tlv_max_roundtrip")
int bpf_geneve_63_tlv_max_roundtrip_check(const struct __ctx_buff *ctx)
{
	const struct bpf_geneve_metadata *meta;
	const struct geneve_opt_hdr *tlv_first;
	const struct geneve_opt_hdr *tlv_mid;
	const struct geneve_opt_hdr *tlv_last;
	struct ethhdr *eth;
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != 0)
		test_fatal("63-TLV roundtrip returned error: %d", *status_code);

	if (max_tlv_wire_proto != bpf_htons(ETH_P_TEB))
		test_fatal("expected wire protocol ETH_P_TEB (0x%x), got 0x%x",
			   ETH_P_TEB, bpf_ntohs(max_tlv_wire_proto));

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("restored eth out of bounds");

	if (memcmp(eth->h_source, (const void *)SRC_MAC, ETH_ALEN) != 0 ||
	    memcmp(eth->h_dest, (const void *)DST_MAC, ETH_ALEN) != 0 ||
	    eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("restored inner Ethernet header corrupted after 63-TLV decap");

	meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_INGRESS);
	if (!meta || meta->magic != BPF_GENEVE_META_MAGIC)
		test_fatal("geneve metadata missing after 63-TLV decap");

	if (meta->opt_len != BPF_GENEVE_OPT_MAX_LEN)
		test_fatal("expected opt_len %u (252 bytes), got %u",
			   BPF_GENEVE_OPT_MAX_LEN, meta->opt_len);

	if (max_tlv_key.tunnel_id != TEST_VNI)
		test_fatal("expected VNI 0x%x, got 0x%x", TEST_VNI, max_tlv_key.tunnel_id);

	/* Verify TLV #1 (index 0, offset 0) */
	tlv_first = bpf_geneve_find_opt(meta, bpf_htons(0x1000), 0);
	if (!tlv_first || tlv_first->type != 0 || tlv_first->length != 0)
		test_fatal("failed to find TLV #1 (index 0)");

	/* Verify TLV #32 (index 31, offset 124) */
	tlv_mid = bpf_geneve_find_opt(meta, bpf_htons(0x1000 + 31), 31);
	if (!tlv_mid || tlv_mid->type != 31 || tlv_mid->length != 0)
		test_fatal("failed to find TLV #32 (index 31)");

	/* Verify TLV #63 (index 62, offset 248 - final word of 252-byte max payload) */
	tlv_last = bpf_geneve_find_opt(meta, bpf_htons(0x1000 + 62), 62);
	if (!tlv_last || tlv_last->type != 62 || tlv_last->length != 0)
		test_fatal("failed to find TLV #63 (index 62 at byte offset 248)");

	test_finish();
}

/* Test 2: Geneve Option Extraction via Overloaded ctx_get_tunnel_opt()
 * Verifies:
 * - Overloaded ctx_get_tunnel_opt (bpf_geneve_get_tunnel_opt) extracts DSR options
 *   transparently from cilium_geneve_meta[BPF_GENEVE_DIR_INGRESS]
 * - Requesting size > meta->opt_len returns -EINVAL
 */
struct dsr_and_custom_opts {
	struct geneve_dsr_opt4 dsr;
	struct geneve_opt_hdr custom_hdr;
	__u32 custom_val;
} __packed;

static struct bpf_tunnel_key opt_extract_key;

PKTGEN("tc", "geneve_opt_extraction_and_overload")
int bpf_geneve_opt_extraction_pktgen(struct __ctx_buff *ctx)
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

static struct geneve_dsr_opt4 extracted_dsr;
static int extracted_dsr_ret;
static int oversized_opt_ret;

SETUP("tc", "geneve_opt_extraction_and_overload")
int bpf_geneve_opt_extraction_setup(struct __ctx_buff *ctx)
{
	struct dsr_and_custom_opts opts = {
		.dsr = {
			.hdr = {
				.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
				.type = DSR_GENEVE_OPT_TYPE,
				.length = 2,
			},
			.addr = bpf_htonl(0x0A600064), /* 10.96.0.100 */
			.port = bpf_htons(8080),
		},
		.custom_hdr = {
			.opt_class = bpf_htons(0x0200),
			.type = 0x08,
			.length = 1,
		},
		.custom_val = bpf_htonl(0xCAFEBABE),
	};
	struct geneve_dsr_opt4 local_dsr = {};
	__u8 oversized_buf[32] = {};
	int ret;

	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IP), &opts, sizeof(opts));
	if (ret < 0)
		return ret;

	ret = bpf_geneve_decap4(ctx, &opt_extract_key);
	if (ret < 0)
		return ret;

	/* Extract DSR option via overloaded ctx_get_tunnel_opt */
	extracted_dsr_ret = ctx_get_tunnel_opt(ctx, &local_dsr, sizeof(local_dsr));
	extracted_dsr = local_dsr;

	/* Negative test: requesting size larger than opt_len (32 > 20) must return -EINVAL */
	oversized_opt_ret = ctx_get_tunnel_opt(ctx, oversized_buf, sizeof(oversized_buf));

	return 0;
}

CHECK("tc", "geneve_opt_extraction_and_overload")
int bpf_geneve_opt_extraction_check(const struct __ctx_buff *ctx)
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
		test_fatal("opt extraction setup returned error: %d", *status_code);

	if (extracted_dsr_ret != sizeof(struct dsr_and_custom_opts))
		test_fatal("expected ctx_get_tunnel_opt return %lu, got %d",
			   sizeof(struct dsr_and_custom_opts), extracted_dsr_ret);

	if (extracted_dsr.hdr.opt_class != bpf_htons(DSR_GENEVE_OPT_CLASS) ||
	    extracted_dsr.hdr.type != DSR_GENEVE_OPT_TYPE)
		test_fatal("extracted DSR header class/type mismatch");

	if (extracted_dsr.addr != bpf_htonl(0x0A600064) ||
	    extracted_dsr.port != bpf_htons(8080))
		test_fatal("extracted DSR addr/port mismatch: 0x%x:%u",
			   bpf_ntohl(extracted_dsr.addr), bpf_ntohs(extracted_dsr.port));

	if (oversized_opt_ret != -EINVAL)
		test_fatal("expected -EINVAL (%d) for oversized opt buffer, got %d",
			   -EINVAL, oversized_opt_ret);

	test_finish();
}

/* Test 3: Malformed TLV Boundary Rejection (Negative Test)
 * Verifies:
 * - bpf_geneve_validate_opts rejects a packet whose TLV length exceeds opt_len
 */
PKTGEN("tc", "geneve_malformed_tlv_rejection")
int bpf_geneve_malformed_tlv_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_malformed_tlv_rejection")
int bpf_geneve_malformed_tlv_setup(struct __ctx_buff *ctx)
{
	struct bpf_tunnel_key bad_key = {};
	/* Create an 8-byte option buffer where TLV claims length = 5 words (20 bytes payload -> 24 bytes > 8 bytes!) */
	struct {
		struct geneve_opt_hdr bad_hdr;
		__u32 dummy;
	} __packed malformed_opt = {
		.bad_hdr = {
			.opt_class = bpf_htons(0x0101),
			.type = 0x01,
			.length = 5, /* Exceeds 8-byte opt_len boundary */
		},
		.dummy = 0,
	};
	int ret;

	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IP), &malformed_opt, sizeof(malformed_opt));
	if (ret < 0)
		return ret;

	/* Decap must detect malformed TLV length and return DROP_INVALID */
	return bpf_geneve_decap4(ctx, &bad_key);
}

CHECK("tc", "geneve_malformed_tlv_rejection")
int bpf_geneve_malformed_tlv_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != DROP_INVALID)
		test_fatal("expected DROP_INVALID (%d) for malformed TLV, got %d",
			   DROP_INVALID, *status_code);

	test_finish();
}

/* Test 4: RFC 8926 Section 3.5.2 Unknown Critical TLV Rejection
 * Verifies that an unknown critical TLV (type high bit 0x80 set, opt_class != DSR)
 * is strictly rejected by bpf_geneve_validate_opts() with DROP_INVALID.
 */
struct unknown_crit_tlv_opt {
	struct geneve_opt_hdr hdr;
	__u32 val;
} __packed;

static struct bpf_tunnel_key crit_bad_key;

PKTGEN("tc", "geneve_unknown_critical_tlv_rejection")
int bpf_geneve_unknown_crit_tlv_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_unknown_critical_tlv_rejection")
int bpf_geneve_unknown_crit_tlv_setup(struct __ctx_buff *ctx)
{
	struct unknown_crit_tlv_opt crit_opt = {
		.hdr = {
			.opt_class = bpf_htons(0x0200), /* Unknown class */
			.type = 0x88,                   /* Critical bit (0x80) set */
			.length = 1,
		},
		.val = bpf_htonl(0xDEADBEEF),
	};
	int ret;

	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IP), &crit_opt, sizeof(crit_opt));
	if (ret < 0)
		return ret;

	return bpf_geneve_decap4(ctx, &crit_bad_key);
}

CHECK("tc", "geneve_unknown_critical_tlv_rejection")
int bpf_geneve_unknown_crit_tlv_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != DROP_INVALID)
		test_fatal("expected DROP_INVALID (%d) for unknown critical TLV, got %d",
			   DROP_INVALID, *status_code);

	test_finish();
}

/* Test 4: 5-Tuple UDP Source Port Entropy & LRU Route Cache Hit
 * Verifies:
 * - bpf_geneve_calc_sport() produces deterministic ports in [32768, 65535]
 * - cilium_geneve_routes LRU map lookup bypasses FIB lookup and populates
 *   outer Ethernet MACs (dmac, smac) and redirect ifindex directly
 */
PKTGEN("tc", "geneve_sport_entropy_and_route_cache")
int bpf_geneve_route_cache_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_sport_entropy_and_route_cache")
int bpf_geneve_route_cache_setup(struct __ctx_buff *ctx)
{
	struct geneve_route_entry cached_rt = {
		.dmac = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
		.smac = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
		.ifindex = 77,
		.saddr = TUNNEL_SRC,
	};
	__be32 dst_key = TUNNEL_DST;

	/* Pre-populate cilium_geneve_routes LRU map for TUNNEL_DST */
	map_update_elem(&cilium_geneve_routes, &dst_key, &cached_rt, BPF_ANY);

	/* Prepare egress metadata in cilium_geneve_meta[BPF_GENEVE_DIR_EGRESS] */
	{
		struct bpf_geneve_metadata *meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);

		if (meta) {
			meta->magic = BPF_GENEVE_META_MAGIC;
			meta->vni = TEST_VNI;
			meta->inner_proto = bpf_htons(ETH_P_IP);
			meta->opt_len = 0;
			meta->ip4.daddr = TUNNEL_DST;
		}
	}

	recorded_redirect_ifindex = 0;
	return tail_geneve_encap4(ctx);
}

CHECK("tc", "geneve_sport_entropy_and_route_cache")
int bpf_geneve_route_cache_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *outer_eth, *inner_eth;
	struct geneve_encaphdr4 *hdr;
	__u32 *status_code;
	__u16 sport;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("expected CTX_ACT_REDIRECT (%d), got %d",
			   CTX_ACT_REDIRECT, *status_code);

	if (recorded_redirect_ifindex != 77)
		test_fatal("expected redirect to cached ifindex 77, got %u",
			   recorded_redirect_ifindex);

	outer_eth = (void *)status_code + sizeof(*status_code);
	if ((void *)outer_eth + sizeof(*outer_eth) + sizeof(*hdr) + sizeof(*inner_eth) > data_end)
		test_fatal("outer and inner headers out of bounds");

	/* Verify outer Ethernet MACs match cached_rt */
	if (outer_eth->h_dest[0] != 0xAA || outer_eth->h_dest[5] != 0xFF)
		test_fatal("outer dmac does not match cached route entry");
	if (outer_eth->h_source[0] != 0x11 || outer_eth->h_source[5] != 0x66)
		test_fatal("outer smac does not match cached route entry");

	hdr = (void *)outer_eth + sizeof(*outer_eth);
	if (hdr->geneve.protocol_type != bpf_htons(ETH_P_TEB))
		test_fatal("expected default Geneve protocol_type ETH_P_TEB (0x%x), got 0x%x",
			   ETH_P_TEB, bpf_ntohs(hdr->geneve.protocol_type));

	inner_eth = (void *)(hdr + 1);
	if (memcmp(inner_eth->h_source, (const void *)SRC_MAC, ETH_ALEN) != 0 ||
	    memcmp(inner_eth->h_dest, (const void *)DST_MAC, ETH_ALEN) != 0 ||
	    inner_eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("14-byte inner Ethernet header not preserved after Geneve header");

	sport = bpf_ntohs(hdr->udp.source);

	/* Verify UDP source port is strictly in RFC 8926 ephemeral range [32768, 65535] */
	if (sport < 32768)
		test_fatal("UDP source port %u not in ephemeral range [32768, 65535]", sport);

	test_finish();
}

/* Test 6: Underlay Route Cache TTL Expiration & Re-Learning via FIB Lookup
 * Verifies:
 * - A stale entry in cilium_geneve_routes (age = 90s > BPF_GENEVE_ROUTE_CACHE_TTL_NS = 30s)
 *   is bypassed in tail_geneve_encap4()
 * - fib_lookup is triggered to resolve the updated next-hop MAC and oif (ifindex = 88)
 * - cilium_geneve_routes is refreshed with the new next-hop MAC, ifindex, and current timestamp
 */
PKTGEN("tc", "geneve_route_cache_ttl_expiration")
int bpf_geneve_route_cache_ttl_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_route_cache_pktgen(ctx);
}

SETUP("tc", "geneve_route_cache_ttl_expiration")
int bpf_geneve_route_cache_ttl_setup(struct __ctx_buff *ctx)
{
	struct geneve_route_entry stale_rt = {
		.dmac = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
		.smac = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
		.ifindex = 77,
		.saddr = TUNNEL_SRC,
		.ts = 10ULL * 1000000000ULL, /* Stale: 90s older than mock_now_ns (100s) */
	};
	__be32 dst_key = TUNNEL_DST;
	struct bpf_geneve_metadata *meta;

	mock_now_ns = 100ULL * 1000000000ULL;
	mock_fib_lookup_enable = true;
	mock_fib_lookup_calls = 0;
	recorded_redirect_ifindex = 0;

	map_update_elem(&cilium_geneve_routes, &dst_key, &stale_rt, BPF_ANY);

	meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
	if (meta) {
		meta->magic = BPF_GENEVE_META_MAGIC;
		meta->vni = TEST_VNI;
		meta->inner_proto = bpf_htons(ETH_P_IP);
		meta->opt_len = 0;
		meta->ip4.daddr = TUNNEL_DST;
	}

	return tail_geneve_encap4(ctx);
}

CHECK("tc", "geneve_route_cache_ttl_expiration")
int bpf_geneve_route_cache_ttl_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *outer_eth;
	struct geneve_route_entry *refreshed;
	__be32 dst_key = TUNNEL_DST;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("expected CTX_ACT_REDIRECT (%d), got %d",
			   CTX_ACT_REDIRECT, *status_code);

	if (mock_fib_lookup_calls != 1)
		test_fatal("expected stale cache entry to trigger 1 fib_lookup call, got %u",
			   mock_fib_lookup_calls);

	if (recorded_redirect_ifindex != 88)
		test_fatal("expected redirect to refreshed FIB ifindex 88, got %u",
			   recorded_redirect_ifindex);

	outer_eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(outer_eth + 1) > data_end)
		test_fatal("outer_eth out of bounds");

	if (outer_eth->h_dest[0] != 0xCC || outer_eth->h_dest[5] != 0x11)
		test_fatal("outer dmac was not updated from FIB lookup after TTL expiry");

	refreshed = map_lookup_elem(&cilium_geneve_routes, &dst_key);
	if (!refreshed)
		test_fatal("refreshed route entry missing from cilium_geneve_routes");
	if (refreshed->ifindex != 88 || refreshed->ts != mock_now_ns)
		test_fatal("cilium_geneve_routes entry not updated with new ifindex/ts");

	test_finish();
}

/* Test 7: IPv6 Underlay Route Cache Hit (cilium_geneve_routes6)
 * Verifies:
 * - tail_geneve_encap6() hits cilium_geneve_routes6 when entry is fresh (age < 30s)
 * - Outer Ethernet MACs, outer IPv6 saddr/daddr, and redirect ifindex are populated
 *   directly from cilium_geneve_routes6 without invoking fib_lookup_v6
 */
PKTGEN("tc", "geneve_route6_cache_hit")
int bpf_geneve_route6_cache_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_route_cache_pktgen(ctx);
}

SETUP("tc", "geneve_route6_cache_hit")
int bpf_geneve_route6_cache_setup(struct __ctx_buff *ctx)
{
	union v6addr saddr6 = { .addr = v6_node_one_addr };
	union v6addr daddr6 = { .addr = v6_node_two_addr };
	struct geneve_route6_entry cached_rt6 = {
		.dmac = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 },
		.smac = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC },
		.ifindex = 99,
		.saddr = saddr6,
		.ts = 95ULL * 1000000000ULL, /* Fresh: 5s old (< 30s TTL) */
	};
	struct bpf_geneve_metadata *meta;

	mock_now_ns = 100ULL * 1000000000ULL;
	mock_fib_lookup_enable = false;
	mock_fib_lookup_calls = 0;
	recorded_redirect_ifindex = 0;

	map_update_elem(&cilium_geneve_routes6, &daddr6, &cached_rt6, BPF_ANY);

	meta = bpf_geneve_get_meta_slot(BPF_GENEVE_DIR_EGRESS);
	if (meta) {
		meta->magic = BPF_GENEVE_META_MAGIC;
		meta->vni = TEST_VNI;
		meta->inner_proto = bpf_htons(ETH_P_IP);
		meta->opt_len = 0;
		meta->ip6.daddr = daddr6;
	}

	return tail_geneve_encap6(ctx);
}

CHECK("tc", "geneve_route6_cache_hit")
int bpf_geneve_route6_cache_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *outer_eth;
	struct geneve_encaphdr6 *hdr6;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("expected CTX_ACT_REDIRECT (%d), got %d",
			   CTX_ACT_REDIRECT, *status_code);

	if (recorded_redirect_ifindex != 99)
		test_fatal("expected redirect to cached IPv6 ifindex 99, got %u",
			   recorded_redirect_ifindex);

	outer_eth = (void *)status_code + sizeof(*status_code);
	if ((void *)outer_eth + sizeof(*outer_eth) + sizeof(*hdr6) > data_end)
		test_fatal("outer_eth + hdr6 out of bounds");

	if (outer_eth->h_proto != bpf_htons(ETH_P_IPV6))
		test_fatal("expected outer_eth->h_proto ETH_P_IPV6");
	if (outer_eth->h_dest[0] != 0xDE || outer_eth->h_dest[5] != 0x01)
		test_fatal("outer dmac does not match cilium_geneve_routes6 entry");
	if (outer_eth->h_source[0] != 0x12 || outer_eth->h_source[5] != 0xBC)
		test_fatal("outer smac does not match cilium_geneve_routes6 entry");

	hdr6 = (void *)(outer_eth + 1);
	if (hdr6->ip6.version != 6 || hdr6->ip6.nexthdr != IPPROTO_UDP)
		test_fatal("invalid outer IPv6 header");

	test_finish();
}

/* Test 8: Inner IPv6 5-Tuple Source Port Entropy & DSCP/Traffic Class Preservation
 * Verifies:
 * - bpf_geneve_hash_inner_v6() hashes the inner IPv6 5-tuple + flow label when
 *   ctx->hash == 0 so distinct inner IPv6 TCP flows receive distinct ephemeral
 *   UDP source ports in [32768, 65535]
 * - Inner IPv6 Traffic Class (DSCP/ECN = 0xB8, EF) is preserved into outer IPv4
 *   tos in bpf_geneve_encap4() AND into outer IPv6 Traffic Class in bpf_geneve_encap6()
 */
static __u16 observed_v6_flow1_sport;
static __u16 observed_v6_flow2_sport;
static __u8 observed_v4_outer_tos;
static __u8 observed_v6_outer_tc;

PKTGEN("tc", "geneve_inner_ipv6_sport_entropy_and_tos_preservation")
int bpf_geneve_inner_ipv6_sport_tos_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	eth = pktgen__push_ethhdr(&builder);
	if (!eth)
		return TEST_ERROR;
	memcpy(eth->h_source, (const void *)SRC_MAC, ETH_ALEN);
	memcpy(eth->h_dest, (const void *)DST_MAC, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	ip6 = pktgen__push_default_ipv6hdr(&builder);
	if (!ip6)
		return TEST_ERROR;
	memcpy(&ip6->saddr, (const void *)v6_pod_one, sizeof(struct in6_addr));
	memcpy(&ip6->daddr, (const void *)v6_pod_two, sizeof(struct in6_addr));
	ip6->nexthdr = IPPROTO_TCP;
	/* Set Traffic Class = 0xB8 (EF DSCP 46, upper 4 bits = 0xB, lower 4 bits = 0x8) */
	ip6->priority = 0xB;
	ip6->flow_lbl[0] = 0x81;
	ip6->flow_lbl[1] = 0x23;
	ip6->flow_lbl[2] = 0x45;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = bpf_htons(10001);
	l4->dest = bpf_htons(443);
	l4->syn = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "geneve_inner_ipv6_sport_entropy_and_tos_preservation")
int bpf_geneve_inner_ipv6_sport_tos_setup(struct __ctx_buff *ctx)
{
	union v6addr saddr6 = { .addr = v6_node_one_addr };
	union v6addr daddr6 = { .addr = v6_node_two_addr };
	struct bpf_tunnel_key key = {};
	struct geneve_encaphdr4 hdr4;
	struct geneve_encaphdr6 hdr6;
	__be16 flow2_sport = bpf_htons(20029);
	int ret;

	observed_v6_flow1_sport = 0;
	observed_v6_flow2_sport = 0;
	observed_v4_outer_tos = 0;
	observed_v6_outer_tc = 0;

	/* Flow 1: inner IPv6 TCP source port 10001 over IPv4 Geneve */
	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IPV6), NULL, 0);
	if (ret < 0)
		return ret;
	if (ctx_load_bytes(ctx, ETH_HLEN, &hdr4, sizeof(hdr4)) < 0)
		return DROP_INVALID;

	observed_v6_flow1_sport = bpf_ntohs(hdr4.udp.source);
	observed_v4_outer_tos = hdr4.ip.tos;

	ret = bpf_geneve_decap4(ctx, &key);
	if (ret < 0)
		return ret;

	/* Flow 2: change inner IPv6 TCP source port to 20029 and re-encap */
	if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source),
			    &flow2_sport, sizeof(flow2_sport), 0) < 0)
		return DROP_INVALID;

	ret = bpf_geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
				bpf_htons(ETH_P_IPV6), NULL, 0);
	if (ret < 0)
		return ret;
	if (ctx_load_bytes(ctx, ETH_HLEN, &hdr4, sizeof(hdr4)) < 0)
		return DROP_INVALID;

	observed_v6_flow2_sport = bpf_ntohs(hdr4.udp.source);

	ret = bpf_geneve_decap4(ctx, &key);
	if (ret < 0)
		return ret;

	/* Now encapsulate over IPv6 Geneve and verify outer IPv6 Traffic Class preservation */
	ret = bpf_geneve_encap6(ctx, &saddr6, &daddr6, TEST_VNI,
				bpf_htons(ETH_P_IPV6), NULL, 0);
	if (ret < 0)
		return ret;
	if (ctx_load_bytes(ctx, ETH_HLEN, &hdr6, sizeof(hdr6)) < 0)
		return DROP_INVALID;

	observed_v6_outer_tc = (__u8)((hdr6.ip6.priority << 4) | (hdr6.ip6.flow_lbl[0] >> 4));
	return 0;
}

CHECK("tc", "geneve_inner_ipv6_sport_entropy_and_tos_preservation")
int bpf_geneve_inner_ipv6_sport_tos_check(const struct __ctx_buff *ctx)
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
		test_fatal("setup returned error: %d", *status_code);

	if (observed_v6_flow1_sport < 32768 || observed_v6_flow2_sport < 32768)
		test_fatal("inner IPv6 sport not in ephemeral range [32768, 65535]: %u, %u",
			   observed_v6_flow1_sport, observed_v6_flow2_sport);

	if (observed_v6_flow1_sport == observed_v6_flow2_sport)
		test_fatal("distinct inner IPv6 TCP flows produced identical sport %u",
			   observed_v6_flow1_sport);

	if (observed_v4_outer_tos != 0xB8)
		test_fatal("expected outer IPv4 tos 0xB8 from inner IPv6 TC, got 0x%x",
			   observed_v4_outer_tos);

	if (observed_v6_outer_tc != 0xB8)
		test_fatal("expected outer IPv6 Traffic Class 0xB8, got 0x%x",
			   observed_v6_outer_tc);

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
