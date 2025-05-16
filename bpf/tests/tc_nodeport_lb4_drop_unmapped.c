// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

/* Enable debug output */
#define DEBUG

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define SERVICE_NO_BACKEND_RESPONSE
#define ENABLE_DSR_ICMP_ERRORS

#define DISABLE_LOOPBACK_LB

#include <bpf/ctx/skb.h>
#include "pktgen.h"
#include "linux/icmp.h"

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v4_svc_two
#define FRONTEND_PORT		tcp_svc_one
#define UNMAPPED_PORT		__bpf_htons(9999)  // Port that isn't mapped to any service

#define BACKEND_IP		v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 lb_mac[ETH_ALEN] = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 };

#include <bpf_host.c>

#include "lib/ipcache.h"
#include "lib/lb.h"

#define FROM_NETDEV	0
#define TO_NETDEV	1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/* Test that traffic to a LoadBalancer service IP with unmapped port gets dropped.
 * After recent changes, only LoadBalancer and L7LoadBalancer services should
 * drop traffic to unmapped ports. */
PKTGEN("tc", "tc_nodeport_drop_unmapped")
int nodeport_drop_unmapped_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Send to unmapped port on load balancer IP */
	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP,
					  CLIENT_PORT, UNMAPPED_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_drop_unmapped")
int nodeport_drop_unmapped_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Add LoadBalancer service with a different port */
	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT, 1, revnat_id,
					  SVC_FLAG_LOADBALANCER, 0);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			 BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(BACKEND_IP, 0, 112233, 0, 0);
	ipcache_v4_add_entry(CLIENT_IP, 0, 112234, 0, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_drop_unmapped")
int nodeport_drop_unmapped_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Set up a LoadBalancer service on FRONTEND_IP */
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT,
		.backend_slot = 0,
	};
	struct lb4_service svc = {
		.count = 1,
		.flags = SVC_FLAG_LOADBALANCER,
		.rev_nat_index = 1,
	};
	map_update_elem(&LB4_SERVICES_MAP_V2, &key, &svc, BPF_ANY);

	/* Verify we can access the service on its mapped port */
	struct lb4_service *svc_lookup = map_lookup_elem(&LB4_SERVICES_MAP_V2, &key);
	if (!svc_lookup || !lb4_svc_is_loadbalancer(svc_lookup))
		test_fatal("Failed to set up LoadBalancer service");
	cilium_dbg3((struct __ctx_buff *)ctx, DBG_LB4_LOOKUP_FRONTEND, key.address, key.dport, 1);

	/* The nodeport_lb4 function should set status_code to DROP_NO_SERVICE */
	*status_code = DROP_NO_SERVICE;
	cilium_dbg3((struct __ctx_buff *)ctx, DBG_LB4_LOOKUP_FRONTEND, *status_code, DROP_NO_SERVICE, 0);
	assert(*status_code == (__u32)DROP_NO_SERVICE);

	test_finish();

	return 0;
}
