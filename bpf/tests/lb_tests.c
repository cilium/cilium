// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <bpf/config/node.h>

#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4					1

#define FRONTEND_IP	v4_svc_one
#define FRONTEND_PORT	tcp_svc_one
#define BACKEND_COUNT	1
#define REVNAT_INDEX	1

#include <lib/lb.h>

#include "lib/lb.h"

/* TCP Service, single-scope */
CHECK("tc", "lb4_tcp_single_scope")
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
CHECK("tc", "lb4_tcp_dual_scope")
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
CHECK("tc", "lb4_udp_single_scope")
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
CHECK("tc", "lb4_udp_dual_scope")
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
CHECK("tc", "lb4_proto_mismatch_nowild_single_scope")
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
CHECK("tc", "lb4_proto_mismatch_nowild_dual_scope")
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
CHECK("tc", "lb4_proto_mismatch_wild_single_scope")
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
CHECK("tc", "lb4_proto_mismatch_wild_dual_scope")
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
