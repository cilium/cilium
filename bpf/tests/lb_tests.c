// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <bpf/config/node.h>

#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4					1
#define ENABLE_LB_LEAST_CONNECTION			1
#define LB_LEAST_CONNECTION_CHOICES			2

#define FRONTEND_IP	v4_svc_one
#define FRONTEND_PORT	tcp_svc_one
#define BACKEND_COUNT	1
#define REVNAT_INDEX	1

#include <lib/lb.h>

#include "lib/lb.h"

CHECK(PROG_TYPE, "lb4_least_connection")
int test_lb4_least_connection(struct __ctx_buff *ctx)
{
	const __u32 backend_one = 1;
	const __u32 backend_two = 2;
	struct lb_lc_key lc_one = {
		.backend_id = backend_one,
		.svc_id = REVNAT_INDEX,
	};
	struct lb_lc_key lc_two = {
		.backend_id = backend_two,
		.svc_id = REVNAT_INDEX,
	};
	struct lb_lc_value busy = {
		.opened = 10,
		.closed = 1,
	};
	struct lb_lc_value idle = {
		.opened = 2,
		.closed = 1,
	};
	struct ipv4_ct_tuple tuple = {
		.nexthdr = IPPROTO_TCP,
	};
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_TCP,
	};
	const struct lb4_service *service;
	__u32 gc_closed = 1;
	__u32 selected;

	test_init();

	__lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 2,
			    REVNAT_INDEX, SVC_FLAG_ROUTABLE, 0, false,
			    LB_SELECTION_LEAST_CONNECTION <<
			    LB_ALGORITHM_SHIFT);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, backend_one,
			  v4_pod_one, tcp_svc_one, IPPROTO_TCP, 0);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 2, backend_two,
			  v4_pod_two, tcp_svc_one, IPPROTO_TCP, 0);
	map_update_elem(&cilium_lb_lc, &lc_one, &busy, BPF_ANY);
	map_update_elem(&cilium_lb_lc, &lc_two, &idle, BPF_ANY);

	service = lb4_lookup_service(&key, true);
	assert(service);
	selected = lb4_select_backend_id(ctx, &key, &tuple, service);
	assert(selected == backend_two);

	lb_lc_conn_open(REVNAT_INDEX, backend_two);
	assert(lb_lc_active_connections(REVNAT_INDEX, backend_two) == 2);
	lb_lc_conn_closed(REVNAT_INDEX, backend_two);
	assert(lb_lc_active_connections(REVNAT_INDEX, backend_two) == 1);
	map_update_elem(&cilium_lb_lc_gc, &lc_two, &gc_closed, BPF_ANY);
	assert(lb_lc_active_connections(REVNAT_INDEX, backend_two) == 0);

	map_delete_elem(&cilium_lb_lc, &lc_one);
	map_delete_elem(&cilium_lb_lc, &lc_two);
	map_delete_elem(&cilium_lb_lc_gc, &lc_two);
	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP);

	test_finish();
}

/* TCP Service, single-scope */
CHECK(PROG_TYPE, "lb4_tcp_single_scope")
int test_lb4_tcp_single_scope(__maybe_unused struct __ctx_buff *ctx)
{
	const struct lb4_service *service;
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_TCP,
	};

	test_init();

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP,
			  BACKEND_COUNT, REVNAT_INDEX);

	service = lb4_lookup_service(&key, true);
	assert(service);
	assert(key.scope == LB_LOOKUP_SCOPE_EXT);
	assert(key.proto == IPPROTO_TCP);
	assert(key.dport == FRONTEND_PORT);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP);

	test_finish();
}

/* TCP Service, dual-scope */
CHECK(PROG_TYPE, "lb4_tcp_dual_scope")
int test_lb4_tcp_dual_scope(__maybe_unused struct __ctx_buff *ctx)
{
	const struct lb4_service *service;
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_TCP,
	};

	test_init();

	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP,
				     BACKEND_COUNT, REVNAT_INDEX,
				     0, SVC_FLAG_TWO_SCOPES);

	service = lb4_lookup_service(&key, true);
	assert(service);
	assert(key.scope == LB_LOOKUP_SCOPE_INT);
	assert(key.proto == IPPROTO_TCP);
	assert(key.dport == FRONTEND_PORT);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP);

	test_finish();
}

/* UDP Service, single-scope */
CHECK(PROG_TYPE, "lb4_udp_single_scope")
int test_lb4_udp_single_scope(__maybe_unused struct __ctx_buff *ctx)
{
	const struct lb4_service *service;
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_UDP,
	};

	test_init();

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP,
			  BACKEND_COUNT, REVNAT_INDEX);

	service = lb4_lookup_service(&key, true);
	assert(service);
	assert(key.scope == LB_LOOKUP_SCOPE_EXT);
	assert(key.proto == IPPROTO_UDP);
	assert(key.dport == FRONTEND_PORT);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP);

	test_finish();
}

/* UDP Service, dual-scope */
CHECK(PROG_TYPE, "lb4_udp_dual_scope")
int test_lb4_udp_dual_scope(__maybe_unused struct __ctx_buff *ctx)
{
	const struct lb4_service *service;
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_UDP,
	};

	test_init();

	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP, BACKEND_COUNT,
				     REVNAT_INDEX, 0, SVC_FLAG_TWO_SCOPES);

	service = lb4_lookup_service(&key, true);
	assert(service);
	assert(key.scope == LB_LOOKUP_SCOPE_INT);
	assert(key.proto == IPPROTO_UDP);
	assert(key.dport == FRONTEND_PORT);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP);

	test_finish();
}

/* Protocol mismatch, no wildcard, single scope */
CHECK(PROG_TYPE, "lb4_proto_mismatch_nowild_single_scope")
int test_lb4_proto_mismatch_nowild_single_scope(__maybe_unused struct __ctx_buff *ctx)
{
	const struct lb4_service *service;
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_UDP,
	};

	test_init();

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP,
			  BACKEND_COUNT, REVNAT_INDEX);

	service = lb4_lookup_service(&key, true);
	assert(!service);
	assert(key.scope == LB_LOOKUP_SCOPE_EXT);
	assert(key.proto == IPPROTO_UDP);
	assert(key.dport == FRONTEND_PORT);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP);

	test_finish();
}

/* Protocol mismatch, no wildcard, dual scope */
CHECK(PROG_TYPE, "lb4_proto_mismatch_nowild_dual_scope")
int test_lb4_proto_mismatch_nowild_dual_scope(__maybe_unused struct __ctx_buff *ctx)
{
	const struct lb4_service *service;
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_UDP,
	};

	test_init();

	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, BACKEND_COUNT,
				     REVNAT_INDEX, 0, SVC_FLAG_TWO_SCOPES);

	service = lb4_lookup_service(&key, true);
	assert(!service);
	assert(key.scope == LB_LOOKUP_SCOPE_EXT);
	assert(key.proto == IPPROTO_UDP);
	assert(key.dport == FRONTEND_PORT);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP);

	test_finish();
}

/* Protocol mismatch, with wildcard, single scope */
CHECK(PROG_TYPE, "lb4_proto_mismatch_wild_single_scope")
int test_lb4_proto_mismatch_wild_single_scope(__maybe_unused struct __ctx_buff *ctx)
{
	const struct lb4_service *service;
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_UDP,
	};

	test_init();

	/* Add the real service */
	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP,
			  BACKEND_COUNT, REVNAT_INDEX);

	/* Add the wildcard service */
	lb_v4_add_service(FRONTEND_IP, LB_SVC_WILDCARD_DPORT, LB_SVC_WILDCARD_PROTO,
			  BACKEND_COUNT, REVNAT_INDEX);

	service = lb4_lookup_service(&key, true);
	assert(!service);
	assert(key.scope == LB_LOOKUP_SCOPE_EXT);
	assert(key.proto == IPPROTO_UDP);
	assert(key.dport == FRONTEND_PORT);

	service = lb4_lookup_service(&key, false);
	assert(service);
	assert(key.scope == LB_LOOKUP_SCOPE_EXT);
	assert(key.proto == LB_SVC_WILDCARD_PROTO);
	assert(key.dport == LB_SVC_WILDCARD_DPORT);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP);
	lb_v4_delete_service(FRONTEND_IP, LB_SVC_WILDCARD_DPORT, LB_SVC_WILDCARD_PROTO);

	test_finish();
}

/* Protocol mismatch, with wildcard, dual scope */
CHECK(PROG_TYPE, "lb4_proto_mismatch_wild_dual_scope")
int test_lb4_proto_mismatch_wild_dual_scope(__maybe_unused struct __ctx_buff *ctx)
{
	const struct lb4_service *service;
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_UDP,
	};

	test_init();

	/* Add the real services */
	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP,
				     BACKEND_COUNT, REVNAT_INDEX, 0, SVC_FLAG_TWO_SCOPES);

	/* Add the wildcard service */
	lb_v4_add_service(FRONTEND_IP, LB_SVC_WILDCARD_DPORT, LB_SVC_WILDCARD_PROTO,
			  BACKEND_COUNT, REVNAT_INDEX);

	service = lb4_lookup_service(&key, true);
	assert(!service);
	assert(key.scope == LB_LOOKUP_SCOPE_EXT);
	assert(key.proto == IPPROTO_UDP);
	assert(key.dport == FRONTEND_PORT);

	service = lb4_lookup_service(&key, false);
	assert(service);
	assert(key.scope == LB_LOOKUP_SCOPE_EXT);
	assert(key.proto == LB_SVC_WILDCARD_PROTO);
	assert(key.dport == LB_SVC_WILDCARD_DPORT);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP);
	lb_v4_delete_service(FRONTEND_IP, LB_SVC_WILDCARD_DPORT, LB_SVC_WILDCARD_PROTO);

	test_finish();
}
