// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#undef QUIET_CT
#define ENABLE_NODEPORT 1

/* Define an endpoint ID that we'll use as index into policy maps. */
#define TEST_LXC_ID_LOCAL 233

/* Define host and LXC interface index */
#define TEST_HOST_IFACE 24
#define TEST_LXC_IFACE 25

/* Load the appropriate BPF programs. */
#include "lib/bpf_host.h"

/* Set our host interface index */
ASSIGN_CONFIG(__u32, interface_ifindex, TEST_HOST_IFACE)

#include "nodeport_defaults.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

#ifdef ENABLE_IPV4
/* Below definitions defined in ./scapy/lb_pkt_defs.py */
const __u8 lb4_clusterip[] = {
	SCAPY_BUF_BYTES(lb4_clusterip)
};

const __u8 lb4_clusterip_post_dnat[] = {
	SCAPY_BUF_BYTES(lb4_clusterip_post_dnat)
};

const __u8 lb4_clusterip_udp[] = {
	SCAPY_BUF_BYTES(lb4_clusterip_udp)
};

/* Below definitions defined in ./scapy/tc_unsupported_pkt_defs.py */
const __u8 unsupported_drop_v4_gre_v4_tcp[] = {
	SCAPY_BUF_BYTES(unsupported_drop_v4_gre_v4_tcp)
};

const __u8 unsupported_drop_v4_esp[] = {
	SCAPY_BUF_BYTES(unsupported_drop_v4_esp)
};
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
/* Below definitions defined in ./scapy/lb_pkt_defs.py */
const __u8 lb6_clusterip[] = {
	SCAPY_BUF_BYTES(lb6_clusterip)
};

const __u8 lb6_clusterip_post_dnat[] = {
	SCAPY_BUF_BYTES(lb6_clusterip_post_dnat)
};

const __u8 lb6_clusterip_udp[] = {
	SCAPY_BUF_BYTES(lb6_clusterip_udp)
};

/* Below definitions defined in ./scapy/tc_unsupported_pkt_defs.py */
const __u8 unsupported_drop_v6_gre_v6_tcp[] = {
	SCAPY_BUF_BYTES(unsupported_drop_v6_gre_v6_tcp)
};

const __u8 unsupported_drop_v6_esp[] = {
	SCAPY_BUF_BYTES(unsupported_drop_v6_esp)
};
#endif /* ENABLE_IPV6 */

/* All the following tests rely on a common set of state:
 * - An LB VIP on TCP/80 with a single backend (Pod1)
 * - An LB Wildcard to replicate the LB control plane wildcard logic
 * - An IPCache entry for the VIP with flag_null_route set
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

		/* IPCache entry with null_route flag set */
		ipcache_v6_add_entry_null_route(&lb_vip, 0, WORLD_IPV6_ID, 0, 0);

		/* Pod */
		ipcache_v6_add_entry(&pod_ip, 0, 112233, 0, 0);
		endpoint_v6_add_entry(&pod_ip, TEST_LXC_IFACE, TEST_LXC_ID_LOCAL,
				      0, 0, NULL, NULL);
	} else {
		/* LB VIP */
		lb_v4_add_service(v4_svc_one, tcp_svc_one, IPPROTO_TCP, 1, revnat_id);
		lb_v4_add_backend(v4_svc_one, tcp_svc_one, 1, 124, v4_pod_one,
				  tcp_dst_one, IPPROTO_TCP, 0);

		/* LB wildcard */
		lb_v4_add_service(v4_svc_one, 0, IPPROTO_ANY, 0, revnat_id);

		/* IPCache entry with null_route flag set */
		ipcache_v4_add_entry_null_route(v4_svc_one, 0, WORLD_IPV4_ID, 0, 0);

		/* Pod */
		ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);
		endpoint_v4_add_entry(v4_pod_one, TEST_LXC_IFACE, TEST_LXC_ID_LOCAL,
				      0, 0, 0, NULL, NULL);
	}
}

static __always_inline void
clear_metric(const int metric)
{
	struct metrics_key key = {
		.reason = (__u8)-metric,
		.dir = METRIC_INGRESS
	};
	map_delete_elem(&cilium_metrics, &key);
}

#ifdef ENABLE_IPV4
/* This test uses a legitimate IPv4 packet towards the real LB VIP on TCP/80.
 *
 * Expected result:
 * - Match the real LB VIP for TCP/80 traffic
 * - Trigger DNAT
 * - Return ACT_OK
 *
 * Rationale: LB VIP should always take precedent over:
 * - wildcard service entry
 * - ipcache entry with null_route true
 */
PKTGEN("tc", "tc_unsupported_drop_netdev_lb4_tcp")
int tc_unsupported_drop_netdev_lb4_tcp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, lb4_clusterip, sizeof(lb4_clusterip));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_netdev_lb4_tcp")
int tc_unsupported_drop_netdev_lb4_tcp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, false);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_netdev_lb4_tcp")
int tc_unsupported_drop_netdev_lb4_tcp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_OK */
	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	/* Check the packet. */
	ASSERT_CTX_BUF_OFF("lb4_clusterip_post_dnat",
			   "Ether", ctx, sizeof(__u32),
			   lb4_clusterip_post_dnat,
			   sizeof(lb4_clusterip_post_dnat));

	test_finish();
}

/* This test uses a legitimate IPv4 packet towards the real LB VIP but on UDP/80
 * rather than TCP/80.
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - Match on wildcard LB entry and result in DROP_NO_SERVICE
 * - Return ACT_DROP
 *
 * Rationale: LB wildcard entry should always take precedent over:
 * - ipcache entry with null_route true
 */
PKTGEN("tc", "tc_unsupported_drop_netdev_lb4_udp")
int tc_unsupported_drop_netdev_lb4_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, lb4_clusterip_udp, sizeof(lb4_clusterip_udp));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_netdev_lb4_udp")
int tc_unsupported_drop_netdev_lb4_udp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, false);
	clear_metric(DROP_NO_SERVICE);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_netdev_lb4_udp")
int tc_unsupported_drop_netdev_lb4_udp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-DROP_NO_SERVICE,
		.dir = METRIC_INGRESS
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
	ASSERT_CTX_BUF_OFF("lb4_clusterip_udp",
			   "Ether", ctx, sizeof(__u32),
			   lb4_clusterip_udp,
			   sizeof(lb4_clusterip_udp));

	/* Assert the correct metric was hit */
	assert_metrics_count(key, count);

	test_finish();
}

/* This test uses an illegitimate IPv4 packet towards the real LB VIP on an
 * unsupported protocol (in this case: GRE, containing another IPv4 TCP packet.)
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - No match on LB wildcard
 * - Match on null_route ipcache entry and result in DROP_NULL_ROUTE
 * - Return ACT_DROP
 */
PKTGEN("tc", "tc_unsupported_drop_netdev_v4_gre")
int tc_unsupported_drop_netdev_v4_gre_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, unsupported_drop_v4_gre_v4_tcp,
			sizeof(unsupported_drop_v4_gre_v4_tcp));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_netdev_v4_gre")
int tc_unsupported_drop_netdev_v4_gre_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, false);
	clear_metric(DROP_NULL_ROUTE);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_netdev_v4_gre")
int tc_unsupported_drop_netdev_v4_gre_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-DROP_NULL_ROUTE,
		.dir = METRIC_INGRESS
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
	ASSERT_CTX_BUF_OFF("unsupported_drop_v4_gre_v4_tcp",
			   "Ether", ctx, sizeof(__u32),
			   unsupported_drop_v4_gre_v4_tcp,
			   sizeof(unsupported_drop_v4_gre_v4_tcp));

	/* Assert the correct metric was hit */
	assert_metrics_count(key, count);

	test_finish();
}

/* This test uses an illegitimate IPv4 packet towards the real LB VIP on an
 * unsupported protocol (in this case: ESP).
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - No match on LB wildcard
 * - Match on null_route ipcache entry and result in DROP_NULL_ROUTE
 * - Return ACT_DROP
 */
PKTGEN("tc", "tc_unsupported_drop_netdev_v4_esp")
int tc_unsupported_drop_netdev_v4_esp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, unsupported_drop_v4_esp,
			sizeof(unsupported_drop_v4_esp));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_netdev_v4_esp")
int tc_unsupported_drop_netdev_v4_esp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, false);
	clear_metric(DROP_NULL_ROUTE);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_netdev_v4_esp")
int tc_unsupported_drop_netdev_v4_esp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-DROP_NULL_ROUTE,
		.dir = METRIC_INGRESS
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
	ASSERT_CTX_BUF_OFF("unsupported_drop_v4_esp",
			   "Ether", ctx, sizeof(__u32),
			   unsupported_drop_v4_esp,
			   sizeof(unsupported_drop_v4_esp));

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
 * - Trigger DNAT
 * - Return ACT_OK
 *
 * Rationale: LB VIP should always take precedent over:
 * - wildcard service entry
 * - ipcache entry with null_route true
 */
PKTGEN("tc", "tc_unsupported_drop_netdev_lb6_tcp")
int tc_unsupported_drop_netdev_lb6_tcp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, lb6_clusterip, sizeof(lb6_clusterip));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_netdev_lb6_tcp")
int tc_unsupported_drop_netdev_lb6_tcp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, true);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_netdev_lb6_tcp")
int tc_unsupported_drop_netdev_lb6_tcp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_OK */
	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	/* Check the packet. */
	ASSERT_CTX_BUF_OFF("lb6_clusterip_post_dnat",
			   "Ether", ctx, sizeof(__u32),
			   lb6_clusterip_post_dnat,
			   sizeof(lb6_clusterip_post_dnat));

	test_finish();
}

/* This test uses a legitimate IPv6 packet towards the real LB VIP but on UDP/80
 * rather than TCP/80.
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - Match on wildcard LB entry and result in DROP_NO_SERVICE
 * - Return ACT_DROP
 *
 * Rationale: LB wildcard entry should always take precedent over:
 * - ipcache entry with null_route true
 */
PKTGEN("tc", "tc_unsupported_drop_netdev_lb6_udp")
int tc_unsupported_drop_netdev_lb6_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, lb6_clusterip_udp, sizeof(lb6_clusterip_udp));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_netdev_lb6_udp")
int tc_unsupported_drop_netdev_lb6_udp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, true);
	clear_metric(DROP_NO_SERVICE);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_netdev_lb6_udp")
int tc_unsupported_drop_netdev_lb6_udp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-DROP_NO_SERVICE,
		.dir = METRIC_INGRESS
	};
	__u64 count = 1;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_DROP */
	status_code = data;
	test_log("status_code %d", *status_code);
	assert(*status_code == CTX_ACT_DROP);

	/* Check the packet. */
	ASSERT_CTX_BUF_OFF("lb6_clusterip_udp",
			   "Ether", ctx, sizeof(__u32),
			   lb6_clusterip_udp,
			   sizeof(lb6_clusterip_udp));

	/* Assert the correct metric was hit */
	assert_metrics_count(key, count);

	test_finish();
}

/* This test uses an illegitimate IPv6 packet towards the real LB VIP on an
 * unsupported protocol (in this case: GRE, containing another IPv6 TCP packet.)
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - No match on LB wildcard
 * - Match on null_route ipcache entry and result in DROP_NULL_ROUTE
 * - Return ACT_DROP
 */
PKTGEN("tc", "tc_unsupported_drop_netdev_v6_gre")
int tc_unsupported_drop_netdev_v6_gre_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, unsupported_drop_v6_gre_v6_tcp,
			sizeof(unsupported_drop_v6_gre_v6_tcp));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_netdev_v6_gre")
int tc_unsupported_drop_netdev_v6_gre_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, true);
	clear_metric(DROP_NULL_ROUTE);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_netdev_v6_gre")
int tc_unsupported_drop_netdev_v6_gre_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-DROP_NULL_ROUTE,
		.dir = METRIC_INGRESS
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
	ASSERT_CTX_BUF_OFF("unsupported_drop_v6_gre_v6_tcp",
			   "Ether", ctx, sizeof(__u32),
			   unsupported_drop_v6_gre_v6_tcp,
			   sizeof(unsupported_drop_v6_gre_v6_tcp));

	/* Assert the correct metric was hit */
	assert_metrics_count(key, count);

	test_finish();
}

/* This test uses an illegitimate IPv6 packet towards the real LB VIP on an
 * unsupported protocol (in this case: ESP).
 *
 * Expected result:
 * - No match on the real LB VIP for TCP/80 traffic
 * - No match on LB wildcard
 * - Match on null_route ipcache entry and result in DROP_NULL_ROUTE
 * - Return ACT_DROP
 */
PKTGEN("tc", "tc_unsupported_drop_netdev_v6_esp")
int tc_unsupported_drop_netdev_v6_esp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, unsupported_drop_v6_esp,
			sizeof(unsupported_drop_v6_esp));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_unsupported_drop_netdev_v6_esp")
int tc_unsupported_drop_netdev_v6_esp_setup(struct __ctx_buff *ctx)
{
	setup_test(ctx, true);
	clear_metric(DROP_NULL_ROUTE);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_unsupported_drop_netdev_v6_esp")
int tc_unsupported_drop_netdev_v6_esp_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct metrics_key key = {
		.reason = (__u8)-DROP_NULL_ROUTE,
		.dir = METRIC_INGRESS
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
	ASSERT_CTX_BUF_OFF("unsupported_drop_v6_esp",
			   "Ether", ctx, sizeof(__u32),
			   unsupported_drop_v6_esp,
			   sizeof(unsupported_drop_v6_esp));

	/* Assert the correct metric was hit */
	assert_metrics_count(key, count);

	test_finish();
}
#endif /* ENABLE_IPV6 */
