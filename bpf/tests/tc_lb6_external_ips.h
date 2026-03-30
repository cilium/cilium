/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright Authors of Cilium
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV6 1
#define ENABLE_NODEPORT 1

#ifdef NORTH_SOUTH_TEST
# define CLIENT_IP		v6_ext_node_one
# define HOOK			netdev_receive_packet

#include "lib/bpf_host.h"
#endif

#define CLIENT_PORT		tcp_src_one

#define FRONTEND_IP		v6_ext_node_two
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v6_pod_one
#define BACKEND_PORT		tcp_dst_one

#define NAT_REV_INDEX		1
#define BACKEND_COUNT		1
#define BACKEND_IFINDEX		11
#define BACKEND_ID		124

#include "lib/endpoint.h"
#include "lib/lb.h"
#include "scapy.h"

/* For checking statistics in conntrack map. */
ASSIGN_CONFIG(bool, enable_conntrack_accounting, true)

/* Expected CT tuple to check for conntrack */
#define EXPECTED_CT_TUPLE {\
	.saddr = *(union v6addr *)CLIENT_IP, \
	.sport = FRONTEND_PORT, \
	.daddr = *(union v6addr *)FRONTEND_IP, \
	.dport = CLIENT_PORT, \
	.nexthdr = IPPROTO_TCP, \
	.flags = TUPLE_F_SERVICE }

/* packet defined in ./scapy/lb_pkt_defs.py */
const __u8 lb6_ns_external_ip[] = {
	SCAPY_BUF_BYTES(lb6_ns_external_ip)
};

/* packet defined in ./scapy/lb_pkt_defs.py */
const __u8 lb6_ns_external_ip_post_dnat[] = {
	SCAPY_BUF_BYTES(lb6_ns_external_ip_post_dnat)
};

/* Test that a request for an ExternalIP service is handled correctly */
PKTGEN("tc", "tc_lb6_external_ips")
int lb6_external_ips_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

#ifdef NORTH_SOUTH_TEST
	scapy_push_data(&builder, lb6_ns_external_ip, sizeof(lb6_ns_external_ip));
#endif

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_lb6_external_ips")
int lb6_external_ips_setup(struct __ctx_buff *ctx)
{
	endpoint_v6_add_entry((union v6addr *)BACKEND_IP, BACKEND_IFINDEX, 0, 0, 0,
			      (__u8 *)mac_one, (__u8 *)mac_two);
	lb_v6_add_service_with_flags((union v6addr *)FRONTEND_IP, FRONTEND_PORT,
				     IPPROTO_TCP, BACKEND_COUNT, NAT_REV_INDEX,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_EXTERNAL_IP | SVC_FLAG_EXT_LOCAL_SCOPE,
				     SVC_FLAG_TWO_SCOPES);
	lb_v6_add_backend((union v6addr *)FRONTEND_IP, FRONTEND_PORT, BACKEND_COUNT, BACKEND_ID,
			  (union v6addr *)BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	return HOOK(ctx);
}

CHECK("tc", "tc_lb6_external_ips")
int lb6_external_ips_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ct_entry *ct_entry;
	struct ipv6_ct_tuple tuple = EXPECTED_CT_TUPLE;

	test_init();

	endpoint_v6_del_entry((union v6addr *)BACKEND_IP);

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	status_code = data;

	assert(data + sizeof(__u32) <= data_end)

#ifdef NORTH_SOUTH_TEST
	/* Ensure packet is accepted. */
	assert(*status_code == CTX_ACT_OK);

	/* Ensure packet is correctly DNATed. */
	ASSERT_CTX_BUF_OFF("lb6_ns_external_ip_post_dnat", "Ether", ctx, sizeof(__u32),
			   lb6_ns_external_ip_post_dnat, sizeof(lb6_ns_external_ip_post_dnat));

	/* Ensure CT entry is updated accordingly (SVC). */
	ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	assert(ct_entry);
	assert(ct_entry->packets == 1);
	assert(ct_entry->bytes == sizeof(lb6_ns_external_ip_post_dnat));
#endif

	test_finish();
}
