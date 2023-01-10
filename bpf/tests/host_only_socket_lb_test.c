// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/unspec.h>
#include <bpf/api.h>
#include "lib/common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#undef ENABLE_HEALTH_CHECK
#define ENABLE_SOCKET_LB_HOST_ONLY 1

#define DST_PORT 6000
#define DST_PORT_HOSTNS 6001
#define BACKEND_PORT 7000

#define HAVE_NETNS_COOKIE 1

/* Hardcode the host netns cookie to 0 */
#define HOST_NETNS_COOKIE 0

/* Replace the get_netns_cookie with a version that returns
 * the HOST_NETNS_COOKIE when destination is DST_PORT_HOSTNS
 */
static __always_inline
int my_get_netns_cookie(__maybe_unused const struct bpf_sock_addr *addr)
{
	return addr->user_port == DST_PORT_HOSTNS ? HOST_NETNS_COOKIE : 1;
}

#define get_netns_cookie(ctx) my_get_netns_cookie(ctx)

#include "bpf_sock.c"

#define SVC_KEY_VALUE(_port, _beslot, _beid, _scope) { \
	.key = { \
		.address = v4_svc_one, \
		.dport = (_port), \
		.scope = (_scope), \
		.backend_slot = (_beslot) \
	}, \
	.value = { \
		.flags = SVC_FLAG_ROUTABLE, \
		.count = 1, \
		.rev_nat_index = 1, \
		.backend_id = (_beid) \
	} \
}

#define BE_KEY_VALUE(_beid, _beip) { \
	.key = (_beid), \
	.value = { \
		.address = (_beip), \
		.port = BACKEND_PORT, \
		.proto = IPPROTO_TCP \
	}, \
}

CHECK("xdp", "sock4_xlate_fwd_test")
int test1_check(__maybe_unused struct xdp_md *ctx)
{
	int ret;
	unsigned long i;
	struct bpf_sock_addr addr = {
		.user_port = DST_PORT,
		.user_ip4 = v4_svc_one,
		.protocol = IPPROTO_TCP,
	};
	struct { __u32 key; struct lb4_backend value; } backends[] = {
		BE_KEY_VALUE(1, v4_pod_one),
	};
	struct { struct lb4_key key; struct lb4_service value; } services[] = {
		SVC_KEY_VALUE(DST_PORT, 0, 0, LB_LOOKUP_SCOPE_INT),
		SVC_KEY_VALUE(DST_PORT, 0, 0, LB_LOOKUP_SCOPE_EXT),
		SVC_KEY_VALUE(DST_PORT, 1, 1, LB_LOOKUP_SCOPE_EXT),
		SVC_KEY_VALUE(DST_PORT_HOSTNS, 0, 0, LB_LOOKUP_SCOPE_INT),
		SVC_KEY_VALUE(DST_PORT_HOSTNS, 0, 0, LB_LOOKUP_SCOPE_EXT),
		SVC_KEY_VALUE(DST_PORT_HOSTNS, 1, 1, LB_LOOKUP_SCOPE_EXT),
	};

	/* Insert the service and backend map values */
	for (i = 0; i < ARRAY_SIZE(services); i++)
		map_update_elem(&LB4_SERVICES_MAP_V2, &services[i].key, &services[i].value,
				BPF_ANY);

	for (i = 0; i < ARRAY_SIZE(backends); i++)
		map_update_elem(&LB4_BACKEND_MAP, &backends[i].key, &backends[i].value,
				BPF_ANY);

	test_init();

	/* If netns is not the host, then xlate should be skipped. */
	addr.user_port = DST_PORT;
	ret = __sock4_xlate_fwd(&addr, &addr, false);
	assert(addr.user_ip4 == v4_svc_one);
	assert(addr.user_port == DST_PORT);
	assert(ret == -ENXIO);

	/* If netns is host, then xlate should happen. */
	addr.user_port = DST_PORT_HOSTNS; /* see my_get_netns_cookie */
	ret = __sock4_xlate_fwd(&addr, &addr, false);
	test_log("xlate_fwd: %d", ret);
	test_log("ip %lx", addr.user_ip4);
	test_log("port %d", addr.user_port);
	test_log("ret: %d", ret);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_pod_one);
	assert(addr.user_port == BACKEND_PORT);

	test_finish();
}
