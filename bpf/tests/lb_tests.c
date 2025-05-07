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

/* Service was created with L4 proto differentiation: */
CHECK("tc", "lb4_tcp_single_scope")
int test_lb4_tcp_single_scope(__maybe_unused struct __ctx_buff *ctx)
{
	struct lb4_service *service;
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
	assert(key.proto == IPPROTO_TCP);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP);

	test_finish();
}

/* Dual-scope Service was created with L4 proto differentiation: */
CHECK("tc", "lb4_tcp_dual_scope")
int test_lb4_tcp_dual_scope(__maybe_unused struct __ctx_buff *ctx)
{
	struct lb4_service *service;
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
	assert(key.proto == IPPROTO_TCP);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP);

	test_finish();
}

/* Service was created without L4 proto differentiation: */
CHECK("tc", "lb4_any_proto_single_scope")
int test_lb4_any_proto_single_scope(__maybe_unused struct __ctx_buff *ctx)
{
	struct lb4_service *service;
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_TCP,
	};

	test_init();

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_ANY,
			  BACKEND_COUNT, REVNAT_INDEX);

	service = lb4_lookup_service(&key, true);
	assert(service);
	assert(key.proto == IPPROTO_ANY);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_ANY);

	test_finish();
}

/* Dual-scope Service was created without L4 proto differentiation: */
CHECK("tc", "lb4_any_proto_dual_scope")
int test_lb4_any_proto_dual_scope(__maybe_unused struct __ctx_buff *ctx)
{
	struct lb4_service *service;
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_TCP,
	};

	test_init();

	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT,
				     IPPROTO_ANY, BACKEND_COUNT,
				     REVNAT_INDEX, 0, SVC_FLAG_TWO_SCOPES);

	service = lb4_lookup_service(&key, true);
	assert(service);
	assert(key.proto == IPPROTO_ANY);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_ANY);

	test_finish();
}

/* Dual-scope Service was created with different L4 proto values
 * (due to eg. upgrade from a legacy Cilium version without proto differentiation,
 *  and then changing iTP / eTP from 'Cluster' to 'Local').
 */
CHECK("tc", "lb4_mixed_proto_dual_scope")
int test_lb4_mixed_proto_dual_scope(__maybe_unused struct __ctx_buff *ctx)
{
	struct lb4_service *service;
	struct lb4_key key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.proto = IPPROTO_TCP,
	};

	test_init();

	lb_v4_add_mixed_proto_service_with_flags(FRONTEND_IP, FRONTEND_PORT,
						 IPPROTO_ANY, IPPROTO_TCP,
						 BACKEND_COUNT, REVNAT_INDEX,
						 0, SVC_FLAG_TWO_SCOPES);

	service = lb4_lookup_service(&key, true);
	assert(service);
	assert(key.proto == IPPROTO_TCP);

	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_ANY);
	lb_v4_delete_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP);

	test_finish();
}
