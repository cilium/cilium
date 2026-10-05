// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4			1

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		tcp_src_one
#define BACKEND_IP		v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define NEW_CONN_IP		v4_svc_one
#define NEW_CONN_REVNAT		10
#define ZERO_BACKEND_IP		v4_svc_two
#define ZERO_BACKEND_REVNAT	11
#define RATELIMITED_IP		v4_svc_three
#define RATELIMITED_REVNAT	12

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(bool, enable_scale_to_zero, true)
ASSIGN_CONFIG(bool, enable_no_service_endpoints_routable, true)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"

/* The test framework cannot read the perf ring, so the wake signals are
 * observed through the rate limiter stamp they take: a stamped map value means
 * the emit path ran, an unchanged one means it was suppressed.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} wake_stamp_map __section_maps_btf;

static __always_inline void save_stamp(__u64 stamp)
{
	__u32 zero = 0;

	map_update_elem(&wake_stamp_map, &zero, &stamp, BPF_ANY);
}

static __always_inline __u64 saved_stamp(void)
{
	__u32 zero = 0;
	__u64 *stamp;

	stamp = map_lookup_elem(&wake_stamp_map, &zero);

	return stamp ? *stamp : 0;
}

static __always_inline int build_packet(struct __ctx_buff *ctx, __be32 svc_ip)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, svc_ip,
					  CLIENT_PORT, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "tc_lb_scale_to_zero_wake_new_conn")
int new_conn_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, NEW_CONN_IP);
}

SETUP("tc", "tc_lb_scale_to_zero_wake_new_conn")
int new_conn_setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service(NEW_CONN_IP, tcp_svc_one, IPPROTO_TCP, 1, NEW_CONN_REVNAT);
	lb_v4_add_backend(NEW_CONN_IP, tcp_svc_one, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);
	lb_track_scale_to_zero(NEW_CONN_REVNAT, 0);

	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);
	endpoint_v4_add_entry(BACKEND_IP, 0, 0, 0, 0, 0, NULL, NULL);
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

/* A new connection to a tracked service that still has backends signals
 * demand, so that the service is not scaled back down under us.
 */
CHECK("tc", "tc_lb_scale_to_zero_wake_new_conn")
int new_conn_check(const struct __ctx_buff *ctx)
{
	__u16 rev_nat_index = NEW_CONN_REVNAT;
	struct iphdr *l3;
	void *data_end;
	__u64 *stamp;
	void *data;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 header out of bounds");

	/* Proves the packet went through the new-connection path rather than
	 * ending up in the no-backend handling.
	 */
	if (l3->daddr != BACKEND_IP)
		test_fatal("packet was not translated to the backend");

	stamp = map_lookup_elem(&cilium_scale_to_zero, &rev_nat_index);
	if (!stamp)
		test_fatal("service is no longer tracked");

	assert(*stamp != 0);

	test_finish();
}

PKTGEN("tc", "tc_lb_scale_to_zero_wake_ratelimited")
int ratelimited_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, RATELIMITED_IP);
}

SETUP("tc", "tc_lb_scale_to_zero_wake_ratelimited")
int ratelimited_setup(struct __ctx_buff *ctx)
{
	__u64 now = ktime_get_ns();

	lb_v4_add_service(RATELIMITED_IP, tcp_svc_one, IPPROTO_TCP, 0,
			  RATELIMITED_REVNAT);
	lb_track_scale_to_zero(RATELIMITED_REVNAT, now);
	save_stamp(now);

	return pod_send_packet(ctx);
}

/* A second connection within the rate limit window is still held, but does not
 * signal again.
 */
CHECK("tc", "tc_lb_scale_to_zero_wake_ratelimited")
int ratelimited_check(const struct __ctx_buff *ctx)
{
	__u16 rev_nat_index = RATELIMITED_REVNAT;
	__u32 *status_code;
	void *data_end;
	__u64 *stamp;
	void *data;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == TC_ACT_SHOT);

	stamp = map_lookup_elem(&cilium_scale_to_zero, &rev_nat_index);
	if (!stamp)
		test_fatal("service is no longer tracked");

	assert(*stamp == saved_stamp());

	test_finish();
}

PKTGEN("tc", "tc_lb_scale_to_zero_wake_zero_backend")
int zero_backend_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, ZERO_BACKEND_IP);
}

SETUP("tc", "tc_lb_scale_to_zero_wake_zero_backend")
int zero_backend_setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service(ZERO_BACKEND_IP, tcp_svc_one, IPPROTO_TCP, 0,
			  ZERO_BACKEND_REVNAT);
	lb_track_scale_to_zero(ZERO_BACKEND_REVNAT, 0);

	return pod_send_packet(ctx);
}

/* A held packet asks for the service to be scaled up. */
CHECK("tc", "tc_lb_scale_to_zero_wake_zero_backend")
int zero_backend_check(const struct __ctx_buff *ctx)
{
	__u16 rev_nat_index = ZERO_BACKEND_REVNAT;
	__u32 *status_code;
	void *data_end;
	__u64 *stamp;
	void *data;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == TC_ACT_SHOT);

	stamp = map_lookup_elem(&cilium_scale_to_zero, &rev_nat_index);
	if (!stamp)
		test_fatal("service is no longer tracked");

	assert(*stamp != 0);

	test_finish();
}
