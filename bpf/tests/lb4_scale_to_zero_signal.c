// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Test that lb4_local's no_service path emits a scale-to-zero demand signal.
 * Perf event output cannot be observed here, so assert on the side effect:
 * the datapath sets cilium_scale_to_zero[rev_nat_index].last_emit_ns, which
 * was seeded to 0.
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

	/* Service without backends, tracked for scale-to-zero. */
	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 0, REVNAT_ID);
	map_update_elem(&cilium_scale_to_zero, &sz_key, &sz_seed, BPF_ANY);

	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "lb4_no_backend_signal")
int lb4_no_backend_signal_check(__maybe_unused const struct __ctx_buff *ctx)
{
	struct scale_to_zero_key sz_key = { .svc_id = REVNAT_ID };
	struct scale_to_zero_value *sz_value;

	test_init();

	TEST("no_service-emits-scale-to-zero-signal", {
		sz_value = map_lookup_elem(&cilium_scale_to_zero, &sz_key);
		if (!sz_value)
			test_fatal("scale-to-zero entry missing after no_service path");

		if (sz_value->last_emit_ns == 0)
			test_fatal("no_service path did not emit a scale-to-zero signal");
	})

	test_finish();
}
