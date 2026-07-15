// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* lb4_local holds a tracked zero-backend service (silent drop + demand signal);
 * an untracked one still gets the ICMP reject. Signal asserted via last_emit_ns,
 * as perf output isn't observable here.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_SCALE_TO_ZERO
#define SERVICE_NO_BACKEND_RESPONSE
#define ENABLE_MASQUERADE_IPV4		1

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v4_svc_two
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v4_pod_two

#define REVNAT_ID		1

/* untracked control service */
#define FRONTEND2_IP		v4_svc_three
#define FRONTEND2_PORT		tcp_svc_two
#define CLIENT2_PORT		__bpf_htons(222)
#define REVNAT2_ID		2

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;

#include "lib/bpf_host.h"

ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = FRONTEND_IP})
ASSIGN_CONFIG(bool, enable_no_service_endpoints_routable, true)

#include "lib/ipcache.h"
#include "lib/lb.h"

PKTGEN("tc", "lb4_no_backend_signal")
int lb4_no_backend_signal_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "lb4_no_backend_signal")
int lb4_no_backend_signal_setup(struct __ctx_buff *ctx)
{
	struct scale_to_zero_key sz_key = { .svc_id = REVNAT_ID };
	struct scale_to_zero_value sz_seed = { .last_emit_ns = 0 };

	/* tracked, no backends */
	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 0, REVNAT_ID);
	map_update_elem(&cilium_scale_to_zero, &sz_key, &sz_seed, BPF_ANY);

	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "lb4_no_backend_signal")
int lb4_no_backend_signal_check(const struct __ctx_buff *ctx)
{
	struct scale_to_zero_key sz_key = { .svc_id = REVNAT_ID };
	struct scale_to_zero_value *sz_value;
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	TEST("no_service-emits-scale-to-zero-signal", {
		sz_value = map_lookup_elem(&cilium_scale_to_zero, &sz_key);
		if (!sz_value)
			test_fatal("scale-to-zero entry missing after no_service path");

		if (sz_value->last_emit_ns == 0)
			test_fatal("no_service path did not emit a scale-to-zero signal");
	})

	TEST("tracked-service-drops-silently", {
		data = (void *)(long)ctx_data(ctx);
		data_end = (void *)(long)ctx->data_end;

		if (data + sizeof(__u32) > data_end)
			test_fatal("status code out of bounds");
		status_code = data;

		if (*status_code != CTX_ACT_DROP)
			test_fatal("tracked no-backend service must drop silently, got %d",
				   *status_code);
	})

	test_finish();
}

PKTGEN("tc", "lb4_untracked_no_backend")
int lb4_untracked_no_backend_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND2_IP,
					  CLIENT2_PORT, FRONTEND2_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "lb4_untracked_no_backend")
int lb4_untracked_no_backend_setup(struct __ctx_buff *ctx)
{
	/* untracked, no backends */
	lb_v4_add_service(FRONTEND2_IP, FRONTEND2_PORT, IPPROTO_TCP, 0, REVNAT2_ID);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "lb4_untracked_no_backend")
int lb4_untracked_no_backend_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	TEST("untracked-service-keeps-normal-reject", {
		data = (void *)(long)ctx_data(ctx);
		data_end = (void *)(long)ctx->data_end;

		if (data + sizeof(__u32) > data_end)
			test_fatal("status code out of bounds");
		status_code = data;

		if (*status_code != CTX_ACT_REDIRECT)
			test_fatal("untracked no-backend service must send the ICMP reply, got %d",
				   *status_code);
	})

	test_finish();
}
