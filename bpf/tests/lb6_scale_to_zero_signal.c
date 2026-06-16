// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* IPv6 counterpart of lb4_scale_to_zero_signal.c: test that lb6_local's
 * no_service path emits a scale-to-zero demand signal, asserted via the
 * last_emit_ns side effect as perf event output cannot be observed here.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV6
#define ENABLE_SCALE_TO_ZERO
#undef ENABLE_PER_PACKET_LB
#define SERVICE_NO_BACKEND_RESPONSE

#define CLIENT_IP		v6_pod_one
#define FRONTEND_IP		v6_pod_two
#define FRONTEND_PORT		tcp_svc_one
#define BACKEND_IP		v6_node_two
#define REVNAT_ID		1

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(bool, enable_no_service_endpoints_routable, true)

#include "lib/ipcache.h"
#include "lib/lb.h"

PKTGEN("tc", "lb6_no_backend_signal")
int lb6_no_backend_signal_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)CLIENT_IP, (__u8 *)FRONTEND_IP,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "lb6_no_backend_signal")
int lb6_no_backend_signal_setup(struct __ctx_buff *ctx)
{
	struct scale_to_zero_key sz_key = { .svc_id = REVNAT_ID };
	struct scale_to_zero_value sz_seed = { .last_emit_ns = 0 };
	union v6addr frontend_ip = {};
	union v6addr backend_ip = {};

	/* Service without backends, tracked for scale-to-zero. */
	memcpy(frontend_ip.addr, (void *)FRONTEND_IP, 16);
	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_TCP, 0, REVNAT_ID);
	map_update_elem(&cilium_scale_to_zero, &sz_key, &sz_seed, BPF_ANY);

	memcpy(backend_ip.addr, (void *)BACKEND_IP, 16);
	ipcache_v6_add_entry(&backend_ip, 0, 112233, 0, 0);

	return pod_send_packet(ctx);
}

CHECK("tc", "lb6_no_backend_signal")
int lb6_no_backend_signal_check(__maybe_unused const struct __ctx_buff *ctx)
{
	struct scale_to_zero_key sz_key = { .svc_id = REVNAT_ID };
	struct scale_to_zero_value *sz_value;

	test_init();

	TEST("lb6_no_service-emits-scale-to-zero-signal", {
		sz_value = map_lookup_elem(&cilium_scale_to_zero, &sz_key);
		if (!sz_value)
			test_fatal("scale-to-zero entry missing after no_service path");

		if (sz_value->last_emit_ns == 0)
			test_fatal("lb6_local no_service did not emit a scale-to-zero signal");
	})

	test_finish();
}
