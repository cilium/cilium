/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#undef QUIET_CT
#define ENABLE_NODEPORT 1

/* Turn on USE_BPF_PROG_FOR_INGRESS_POLICY to avoid having to deal with
 * policy tailcalls in this test case.
 */
#define USE_BPF_PROG_FOR_INGRESS_POLICY 1

/* Define an endpoint ID that we'll use as index into policy maps. */
#define TEST_LXC_ID_LOCAL 233

/* Define host and LXC interface index */
#define TEST_HOST_IFACE 24
#define TEST_LXC_IFACE 25

/* Define mac addresses we expect to see on redirected packet */
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *ep_mac = mac_four;

/* Load the appropriate BPF programs. */
#include "lib/bpf_lxc.h"

/* Set our host interface index */
ASSIGN_CONFIG(__u32, interface_ifindex, TEST_HOST_IFACE)

/* Assign necessary load-time configs */
#ifdef ENABLE_IPV4
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(union v4addr, service_loopback_ipv4, { .be32 = v4_svc_loopback })
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(union v6addr, service_loopback_ipv6, { .addr = v6_svc_loopback })
#endif /* ENABLE_IPV6 */

/* Some of the below tests are looking to verify that the datapath will correctly
 * drop unsupported protocols on pod egress. However, the mechanism for this
 * will depend on whether "extended protocol" support is enabled at runtime. This
 * namely covers IGMP and VRRP. By default, this is disabled.
 *
 * If extended protocols are disabled, unsupported protocols will result in an
 * egress CT lookup failure because Cilium can't decode the L4 header. This
 * gives us a hit against DROP_CT_UNKNOWN_PROTO.
 *
 * If extended protocols are enabled, the egress CT lookup will actually zero
 * the sport/dport of the ct_tuple structure and continue, resulting in CT_NEW.
 * This allows processing to continue into the remote destination lookup logic,
 * where we check for flag_unroutable and, if set, return DROP_UNROUTABLE.
 *
 * This test supports both variants.
 */
#ifdef __CONFIG_EXTENDED_PROTOCOLS
ASSIGN_CONFIG(bool, enable_extended_ip_protocols, true)
#define TEST_UNSUPPORTED_DROP_METRIC DROP_UNROUTABLE
#else
ASSIGN_CONFIG(bool, enable_extended_ip_protocols, false)
#define TEST_UNSUPPORTED_DROP_METRIC DROP_CT_UNKNOWN_PROTO
#endif /* __CONFIG_EXTENDED_PROTOCOLS */

#include "nodeport_defaults.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"

/* All the following tests rely on a common set of state:
 * - An LB VIP on TCP/80 with a single backend (Pod1)
 * - An LB Wildcard to replicate the LB control plane wildcard logic
 * - An IPCache entry for the VIP with Unroutable flag set
 *
 * It's worth noting that nothing here should actually hit the wildcard
 * because this is treated as an E/W flow and wildcards are only on
 * external. However, the entry is still setup to ensure the test is
 * suitably complex.
 */
static __always_inline void
setup_test(struct __ctx_buff *ctx __maybe_unused, const bool ipv6)
{
	__u16 revnat_id = 1;

	if (ipv6) {
		union v6addr lb_vip = { .addr = v6_svc_one_addr };
		union v6addr pod_ip = { .addr = v6_pod_one_addr };

		/* LB VIP */
		lb_v6_add_service(&lb_vip, tcp_svc_one, IPPROTO_TCP, 1, revnat_id);
		lb_v6_add_backend(&lb_vip, tcp_svc_one, 1, 124, &pod_ip,
				  tcp_dst_one, IPPROTO_TCP, 0);

		/* LB wildcard */
		lb_v6_add_service(&lb_vip, 0, IPPROTO_ANY, 0, revnat_id);

		/* Unroutable IPCache entry */
		ipcache_v6_add_entry_unroutable(&lb_vip, 0, WORLD_IPV6_ID, 0, 0);

		/* Pod */
		ipcache_v6_add_entry(&pod_ip, 0, 112233, 0, 0);
		endpoint_v6_add_entry(&pod_ip, TEST_LXC_IFACE, TEST_LXC_ID_LOCAL,
				      0, 0, (const __u8 *)ep_mac, (const __u8 *)node_mac);
	} else {
		/* LB VIP */
		lb_v4_add_service(v4_svc_one, tcp_svc_one, IPPROTO_TCP, 1, revnat_id);
		lb_v4_add_backend(v4_svc_one, tcp_svc_one, 1, 124, v4_pod_one,
				  tcp_dst_one, IPPROTO_TCP, 0);

		/* LB wildcard */
		lb_v4_add_service(v4_svc_one, 0, IPPROTO_ANY, 0, revnat_id);

		/* Unroutable IPCache entry */
		ipcache_v4_add_entry_unroutable(v4_svc_one, 0, WORLD_IPV4_ID, 0, 0);

		/* Pod */
		ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);
		endpoint_v4_add_entry(v4_pod_one, TEST_LXC_IFACE, TEST_LXC_ID_LOCAL,
				      0, 0, 0, (const __u8 *)ep_mac, (const __u8 *)node_mac);
	}

	/* We need an open policy for egress */
	policy_add_egress_allow_all_entry();
}

static __always_inline __maybe_unused void
clear_metric(const int metric)
{
	struct metrics_key key = {
		.reason = (__u8)-metric,
		.dir = METRIC_EGRESS,
	};
	map_delete_elem(&cilium_metrics, &key);
}

#ifdef ENABLE_IPV4
/* This test uses a legitimate IPv4 packet towards the real LB VIP on TCP/80.
 *
 * Expected result:
 * - Match the real LB VIP for TCP/80 traffic
 * - Trigger DNAT to backend
 * - Trigger SNAT behind pod service loopback (due to hairpin)
 * - Return ACT_REDIRECT for local delivery
 *
 * Rationale: LB VIP should always take precedent over:
 * - unroutable ipcache entry
 */
PKTGEN("tc", "tc_unsupported_drop_lxc_lb4_tcp")
int tc_unsupported_drop_lxc_lb4_tcp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(LB4_CLUSTERIP_HAIRPIN_TCP_PRE, lb4_clusterip_hairpin_tcp_prenat);
	BUILDER_PUSH_BUF(builder, LB4_CLUSTERIP_HAIRPIN_TCP_PRE);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_lxc_lb4_tcp")
int tc_unsupported_drop_lxc_lb4_tcp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, false);
	return pod_send_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_lxc_lb4_tcp")
int tc_unsupported_drop_lxc_lb4_tcp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_REDIRECT */
	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	/* Check the packet. */
	BUF_DECL(LB4_CLUSTERIP_HAIRPIN_TCP_POST, lb4_clusterip_hairpin_tcp_postnat);
	ASSERT_CTX_BUF_OFF("lb4_clusterip_hairpin_tcp_postnat",
			   "Ether", ctx, sizeof(__u32),
			   LB4_CLUSTERIP_HAIRPIN_TCP_POST,
			   sizeof(BUF(LB4_CLUSTERIP_HAIRPIN_TCP_POST)));

	test_finish();
}

/* This test uses a legitimate IPv4 packet towards the real LB VIP but on UDP/80
 * rather than TCP/80.
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - LB wildcards are not checked because this is an E/W flow
 * - Match on unroutable IPCache entry and result in DROP_UNROUTABLE
 * - Return ACT_DROP
 */
PKTGEN("tc", "tc_unsupported_drop_lxc_lb4_udp")
int tc_unsupported_drop_lxc_lb4_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(LB4_CLUSTERIP_UDP_PRE, lb4_clusterip_udp);
	BUILDER_PUSH_BUF(builder, LB4_CLUSTERIP_UDP_PRE);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_lxc_lb4_udp")
int tc_unsupported_drop_lxc_lb4_udp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, false);
	clear_metric(DROP_UNROUTABLE);
	return pod_send_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_lxc_lb4_udp")
int tc_unsupported_drop_lxc_lb4_udp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNROUTABLE,
		.dir = METRIC_EGRESS
	};
	__u64 count = 1;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_DROP */
	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	/* Check the packet. */
	BUF_DECL(LB4_CLUSTERIP_UDP_POST, lb4_clusterip_udp);
	ASSERT_CTX_BUF_OFF("lb4_clusterip_udp",
			   "Ether", ctx, sizeof(__u32),
			   LB4_CLUSTERIP_UDP_POST,
			   sizeof(BUF(LB4_CLUSTERIP_UDP_POST)));

	/* Assert the correct metric was hit */
	assert_metrics_count(key, count);

	test_finish();
}

/* This test uses an illegitimate IPv4 packet towards the real LB VIP on an
 * unsupported protocol (in this case: GRE, containing another IPv4 TCP packet.)
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - LB wildcards are not checked because this is an E/W flow
 * - If ExtendedProtocols:
 *     Match on unroutable IPCache entry -> DROP_UNROUTABLE
 *   Else:
 *     CT egress decode failure -> DROP_CT_UNKNOWN_PROTO
 * - Return ACT_DROP
 */
PKTGEN("tc", "tc_unsupported_drop_lxc_lb4_gre")
int tc_unsupported_drop_lxc_lb4_gre_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(UNSUPPORTED_DROP_V4_GRE_V4_TCP_PRE, unsupported_drop_v4_gre_v4_tcp);
	BUILDER_PUSH_BUF(builder, UNSUPPORTED_DROP_V4_GRE_V4_TCP_PRE);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_lxc_lb4_gre")
int tc_unsupported_drop_lxc_lb4_gre_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, false);
	clear_metric(TEST_UNSUPPORTED_DROP_METRIC);
	return pod_send_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_lxc_lb4_gre")
int tc_unsupported_drop_lxc_lb4_gre_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-TEST_UNSUPPORTED_DROP_METRIC,
		.dir = METRIC_EGRESS
	};
	__u64 count = 1;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_REDIRECT */
	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	/* Check the packet. */
	BUF_DECL(UNSUPPORTED_DROP_V4_GRE_V4_TCP_POST, unsupported_drop_v4_gre_v4_tcp);
	ASSERT_CTX_BUF_OFF("unsupported_drop_v4_gre_v4_tcp",
			   "Ether", ctx, sizeof(__u32),
			   UNSUPPORTED_DROP_V4_GRE_V4_TCP_POST,
			   sizeof(BUF(UNSUPPORTED_DROP_V4_GRE_V4_TCP_POST)));

	/* Assert the correct metric was hit */
	assert_metrics_count(key, count);

	test_finish();
}

/* This test uses an illegitimate IPv4 packet towards the real LB VIP on an
 * unsupported protocol (in this case: ESP).
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - LB wildcards are not checked because this is an E/W flow
 * - If ExtendedProtocols:
 *     Match on unroutable IPCache entry -> DROP_UNROUTABLE
 *   Else:
 *     CT egress decode failure -> DROP_CT_UNKNOWN_PROTO
 * - Return ACT_DROP
 */
PKTGEN("tc", "tc_unsupported_drop_lxc_lb4_esp")
int tc_unsupported_drop_lxc_lb4_esp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(UNSUPPORTED_DROP_V4_ESP_PRE, unsupported_drop_v4_esp);
	BUILDER_PUSH_BUF(builder, UNSUPPORTED_DROP_V4_ESP_PRE);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_lxc_lb4_esp")
int tc_unsupported_drop_lxc_lb4_esp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, false);
	clear_metric(TEST_UNSUPPORTED_DROP_METRIC);
	return pod_send_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_lxc_lb4_esp")
int tc_unsupported_drop_lxc_lb4_esp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-TEST_UNSUPPORTED_DROP_METRIC,
		.dir = METRIC_EGRESS
	};
	__u64 count = 1;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_REDIRECT */
	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	/* Check the packet. */
	BUF_DECL(UNSUPPORTED_DROP_V4_ESP_POST, unsupported_drop_v4_esp);
	ASSERT_CTX_BUF_OFF("unsupported_drop_v4_esp",
			   "Ether", ctx, sizeof(__u32),
			   UNSUPPORTED_DROP_V4_ESP_POST,
			   sizeof(BUF(UNSUPPORTED_DROP_V4_ESP_POST)));

	/* Assert the correct metric was hit */
	assert_metrics_count(key, count);

	test_finish();
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
/* This test uses a legitimate IPv6 packet towards the real LB VIP on TCP/80.
 *
 * Expected result:
 * - Match the real LB VIP for TCP/80 traffic
 * - Trigger DNAT to backend
 * - Trigger SNAT behind pod service loopback (due to hairpin)
 * - Return ACT_REDIRECT for local delivery
 *
 * Rationale: LB VIP should always take precedent over:
 * - unroutable ipcache entry
 */
PKTGEN("tc", "tc_unsupported_drop_lxc_lb6_tcp")
int tc_unsupported_drop_lxc_lb6_tcp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(LB6_CLUSTERIP_HAIRPIN_TCP_PRE, lb6_clusterip_hairpin_tcp_prenat);
	BUILDER_PUSH_BUF(builder, LB6_CLUSTERIP_HAIRPIN_TCP_PRE);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_lxc_lb6_tcp")
int tc_unsupported_drop_lxc_lb6_tcp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, true);
	return pod_send_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_lxc_lb6_tcp")
int tc_unsupported_drop_lxc_lb6_tcp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_REDIRECT */
	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	/* Check the packet. */
	BUF_DECL(LB6_CLUSTERIP_HAIRPIN_TCP_POST, lb6_clusterip_hairpin_tcp_postnat);
	ASSERT_CTX_BUF_OFF("lb6_clusterip_hairpin_tcp_postnat",
			   "Ether", ctx, sizeof(__u32),
			   LB6_CLUSTERIP_HAIRPIN_TCP_POST,
			   sizeof(BUF(LB6_CLUSTERIP_HAIRPIN_TCP_POST)));

	test_finish();
}

/* This test uses a legitimate IPv6 packet towards the real LB VIP but on UDP/80
 * rather than TCP/80.
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - LB wildcards are not checked because this is an E/W flow
 * - Match on unroutable IPCache entry and result in DROP_UNROUTABLE
 * - Return ACT_DROP
 */
PKTGEN("tc", "tc_unsupported_drop_lxc_lb6_udp")
int tc_unsupported_drop_lxc_lb6_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(LB6_CLUSTERIP_UDP_PRE, lb6_clusterip_udp);
	BUILDER_PUSH_BUF(builder, LB6_CLUSTERIP_UDP_PRE);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_lxc_lb6_udp")
int tc_unsupported_drop_lxc_lb6_udp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, true);
	clear_metric(DROP_UNROUTABLE);
	return pod_send_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_lxc_lb6_udp")
int tc_unsupported_drop_lxc_lb6_udp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNROUTABLE,
		.dir = METRIC_EGRESS
	};
	__u64 count = 1;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_DROP */
	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	/* Check the packet. */
	BUF_DECL(LB6_CLUSTERIP_UDP_POST, lb6_clusterip_udp);
	ASSERT_CTX_BUF_OFF("lb6_clusterip_udp",
			   "Ether", ctx, sizeof(__u32),
			   LB6_CLUSTERIP_UDP_POST,
			   sizeof(BUF(LB6_CLUSTERIP_UDP_POST)));

	/* Assert the correct metric was hit */
	assert_metrics_count(key, count);

	test_finish();
}

/* This test uses an illegitimate IPv6 packet towards the real LB VIP on an
 * unsupported protocol (in this case: GRE, containing another IPv6 TCP packet.)
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - LB wildcards are not checked because this is an E/W flow
 * - If ExtendedProtocols:
 *     Match on unroutable IPCache entry -> DROP_UNROUTABLE
 *   Else:
 *     CT egress decode failure -> DROP_CT_UNKNOWN_PROTO
 * - Return ACT_DROP
 */
PKTGEN("tc", "tc_unsupported_drop_lxc_lb6_gre")
int tc_unsupported_drop_lxc_lb6_gre_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(UNSUPPORTED_DROP_V6_GRE_V6_TCP_PRE, unsupported_drop_v6_gre_v6_tcp);
	BUILDER_PUSH_BUF(builder, UNSUPPORTED_DROP_V6_GRE_V6_TCP_PRE);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_lxc_lb6_gre")
int tc_unsupported_drop_lxc_lb6_gre_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, true);
	clear_metric(TEST_UNSUPPORTED_DROP_METRIC);
	return pod_send_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_lxc_lb6_gre")
int tc_unsupported_drop_lxc_lb6_gre_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-TEST_UNSUPPORTED_DROP_METRIC,
		.dir = METRIC_EGRESS
	};
	__u64 count = 1;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_REDIRECT */
	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	/* Check the packet. */
	BUF_DECL(UNSUPPORTED_DROP_V6_GRE_V6_TCP_POST, unsupported_drop_v6_gre_v6_tcp);
	ASSERT_CTX_BUF_OFF("unsupported_drop_v6_gre_v6_tcp",
			   "Ether", ctx, sizeof(__u32),
			   UNSUPPORTED_DROP_V6_GRE_V6_TCP_POST,
			   sizeof(BUF(UNSUPPORTED_DROP_V6_GRE_V6_TCP_POST)));

	/* Assert the correct metric was hit */
	assert_metrics_count(key, count);

	test_finish();
}

/* This test uses an illegitimate IPv6 packet towards the real LB VIP on an
 * unsupported protocol (in this case: ESP).
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - LB wildcards are not checked because this is an E/W flow
 * - If ExtendedProtocols:
 *     Match on unroutable IPCache entry -> DROP_UNROUTABLE
 *   Else:
 *     CT egress decode failure -> DROP_CT_UNKNOWN_PROTO
 * - Return ACT_DROP
 */
PKTGEN("tc", "tc_unsupported_drop_lxc_lb6_esp")
int tc_unsupported_drop_lxc_lb6_esp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(UNSUPPORTED_DROP_V6_ESP_PRE, unsupported_drop_v6_esp);
	BUILDER_PUSH_BUF(builder, UNSUPPORTED_DROP_V6_ESP_PRE);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_lxc_lb6_esp")
int tc_unsupported_drop_lxc_lb6_esp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, true);
	clear_metric(TEST_UNSUPPORTED_DROP_METRIC);
	return pod_send_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_lxc_lb6_esp")
int tc_unsupported_drop_lxc_lb6_esp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-TEST_UNSUPPORTED_DROP_METRIC,
		.dir = METRIC_EGRESS
	};
	__u64 count = 1;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_DROP */
	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	/* Check the packet. */
	BUF_DECL(UNSUPPORTED_DROP_V6_ESP_POST, unsupported_drop_v6_esp);
	ASSERT_CTX_BUF_OFF("unsupported_drop_v6_esp",
			   "Ether", ctx, sizeof(__u32),
			   UNSUPPORTED_DROP_V6_ESP_POST,
			   sizeof(BUF(UNSUPPORTED_DROP_V6_ESP_POST)));

	/* Assert the correct metric was hit */
	assert_metrics_count(key, count);

	test_finish();
}
#endif /* ENABLE_IPV4 */
