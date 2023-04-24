// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>

#include "node_config.h"

#define ENDPOINTS_MAP test_cilium_lxc
#define POLICY_PROG_MAP_SIZE ENDPOINTS_MAP_SIZE
#define METRICS_MAP test_cilium_metrics

#define ENDPOINTS_MAP_SIZE 65536
#define IPCACHE_MAP_SIZE 512000
#define METRICS_MAP_SIZE 65536
#define EVENTS_MAP test_cilium_events

#define ENABLE_IPV4
#undef ENABLE_IPV6
#define SKIP_POLICY_MAP
#define ENABLE_NODEPORT
#define ENABLE_IP_MASQ_AGENT
#define SNAT_MAPPING_IPV4_SIZE 524288
#define CT_MAP_TCP6 test_cilium_ct_tcp6_65535
#define CT_MAP_ANY6 test_cilium_ct_any6_65535
#define CT_MAP_TCP4 test_cilium_ct_tcp4_65535
#define CT_MAP_ANY4 test_cilium_ct_any4_65535
#define CT_MAP_SIZE_TCP 4096
#define CT_MAP_SIZE_ANY 4096
#define CT_CONNECTION_LIFETIME_TCP	21600
#define CT_CONNECTION_LIFETIME_NONTCP	60
#define CT_SERVICE_LIFETIME_TCP		21600
#define CT_SERVICE_LIFETIME_NONTCP	60
#define CT_SERVICE_CLOSE_REBALANCE	30
#define CT_SYN_TIMEOUT			60
#define CT_CLOSE_TIMEOUT		10
#define CT_REPORT_INTERVAL		5
#define CT_REPORT_FLAGS			0xff

#define NODEPORT_PORT_MAX 32767
#define NODEPORT_PORT_MIN_NAT (NODEPORT_PORT_MAX + 1)

#define DIRECT_ROUTING_DEV_IFINDEX 0

#include "lib/conntrack.h"

#define ct_lazy_lookup4 mock_ct_lazy_lookup4
#define ct_create4 mock_ct_create4

#include "lib/common.h"
#include "lib/csum.h"
#include "lib/l4.h"

#define __LIB_CONNTRACK_H_

static int mock_ct_lazy_lookup4_response = -1;
static __always_inline int mock_ct_lazy_lookup4(__maybe_unused const void *map,
						__maybe_unused struct ipv4_ct_tuple *tuple,
						__maybe_unused struct __ctx_buff *ctx,
						__maybe_unused int off,
						__maybe_unused bool has_l4_header,
						__maybe_unused int action,
						__maybe_unused enum ct_dir dir,
						__maybe_unused struct ct_state *ct_state,
						__maybe_unused __u32 *monitor)
{
	return mock_ct_lazy_lookup4_response;
}

static int mock_ct_create4_response = 1;
static __always_inline int mock_ct_create4(__maybe_unused const void *map_main,
					   __maybe_unused const void *map_related,
					   __maybe_unused struct ipv4_ct_tuple *tuple,
					   __maybe_unused struct __ctx_buff *ctx,
					   __maybe_unused const int dir,
					   __maybe_unused const struct ct_state *ct_state,
					   __maybe_unused bool proxy_redirect,
					   __maybe_unused bool from_l7lb,
					   __maybe_unused __s8 *ext_err)
{
	return mock_ct_create4_response;
}

#define __lookup_ip4_endpoint      mock__lookup_ip4_endpoint
#define lookup_ip4_remote_endpoint mock_lookup_ip4_remote_endpoint

static __always_inline struct endpoint_info *mock__lookup_ip4_endpoint(__maybe_unused __u32 ip)
{
	return NULL;
}

static __always_inline struct remote_endpoint_info *
mock_lookup_ip4_remote_endpoint(__maybe_unused __u32 ip, __maybe_unused __u8 cluster_id)
{
	return NULL;
}

#include "lib/nat.h"
#include "bpf/section.h"

CHECK("xdp", "nat")
int bpf_test(__maybe_unused struct xdp_md *ctx)
{
	test_init();

	struct __ctx_buff ctx_buff;
	struct ipv4_ct_tuple tuple;

	/* If there is an error in ct_lazy_lookup4, it will return a negative value. We */
	/* can simply assume it to be -1 because the actually value does not matter. */
	mock_ct_lazy_lookup4_response = -1;

	/* So snat_v4_track_connection will return exactly the same value which means */
	/* an error occurs when snat_v4_track_connection is looking for the ipv4_ct_tuple. */
	TEST("return -1 on error", {
		if (snat_v4_track_connection(&ctx_buff, &tuple, true, ACTION_CREATE,
					     NAT_DIR_EGRESS, 0, NULL) != -1) {
			test_fail();
		}
	});

	/* If ct_lazy_lookup4 finds an entry, it will return a positive value. We can */
	/* also assume it to be 1 because the actually value does not matter. */
	mock_ct_lazy_lookup4_response = 1;

	/* So snat_v4_track_connection will return 0 which means snat_v4_track_connection */
	/* successfully tracks ipv4_ct_tuple. */
	TEST("return 0 on track", {
		if (snat_v4_track_connection(&ctx_buff, &tuple, true, ACTION_CREATE,
					     NAT_DIR_EGRESS, 0, NULL) != 0) {
			test_fail();
		}
	});

	/* If ct_lazy_lookup4 does not find an entry, it will return CT_NEW which equals */
	/* to zero. Then if ct_create4 fails creating the entry, it will return a */
	/* negative value which is assumed as -1 since the actual value does not */
	/* matter. */
	mock_ct_lazy_lookup4_response = CT_NEW;
	mock_ct_create4_response = -1;

	/* So snat_v4_track_connection will return that value which means an error occurs */
	/* when snat_v4_track_connection is trying to create the ipv4_ct_tuple. */
	TEST("return -1 on create error", {
		if (snat_v4_track_connection(&ctx_buff, &tuple, true, ACTION_CREATE,
					     NAT_DIR_EGRESS, 0, NULL) != -1) {
			test_fail();
		}
	});

	/* If ct_lazy_lookup4 does not find an entry, it will return CT_NEW which equals */
	/* to zero. Then if ct_create4 successfully creates the entry, it will */
	/* return 0. */
	mock_ct_lazy_lookup4_response = CT_NEW;
	mock_ct_create4_response = 0;

	/* So snat_v4_track_connection will return 0 which means snat_v4_track_connection */
	/* successfully creates the ipv4_ct_tuple. */
	TEST("return 0 on create success", {
		if (snat_v4_track_connection(&ctx_buff, &tuple, true, ACTION_CREATE,
					     NAT_DIR_EGRESS, 0, NULL) != 0) {
			test_fail();
		}
	});

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
