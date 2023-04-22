// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/unspec.h>
#include <bpf/api.h>
#include "lib/common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1

#define ENABLE_HOST_SERVICES_TCP 1
#undef ENABLE_HEALTH_CHECK
#define ENABLE_SOCKET_LB_HOST_ONLY 1
#define ENABLE_SOCKET_LB_TCP
#define ENABLE_SOCKET_LB_UDP

#define ENABLE_NODEPORT 1

#define BPF_HAVE_NETNS_COOKIE 1

/* Hardcode the host netns cookie to 0 */
#define HOST_NETNS_COOKIE 0

#include "bpf_sock.c"

enum {
	NODEPORT_LOOKUP = 0,
	HOSTPORT_LOOKUP = 1,
};

enum {
	DONT_INCLUDE_REMOTE_HOSTS = 0,
	INCLUDE_REMOTE_HOSTS = 1,
};

enum {
	OTHER_NS = 0,
	HOST_NS = 1,
};

#define DONT_CARE(x) x

enum {
	NODEPORT_EXISTS = NODEPORT_PORT_MIN + 1,
	HOSTPORT_EXISTS = NODEPORT_PORT_MIN - 1,
	HOSTPORT_EXISTS_LOCALHOST = NODEPORT_PORT_MIN - 2,
};

#define SVC_KEY_VALUE(ADDR, PORT, FLAGS, FLAGS2) {	\
	.key = {					\
		.address = bpf_htonl(ADDR),		\
		.dport = bpf_htons(PORT),		\
	},						\
	.value = {					\
		.count = 1,				\
		.flags = (FLAGS),			\
		.flags2 = (FLAGS2),			\
	}						\
}

#define SVC_KEY_VALUE_V6(ADDR, PORT, FLAGS, FLAGS2) {	\
	.key = {					\
		.address = *(ADDR),			\
		.dport = bpf_htons(PORT),		\
	},						\
	.value = {					\
		.count = 1,				\
		.flags = (FLAGS),			\
		.flags2 = (FLAGS2),			\
	}						\
}

enum {
	HOST_IP = 0x12345678,
};

static inline void __setup_v4(void)
{
	struct remote_endpoint_info cache_value = {};
	struct ipcache_key cache_key = {};
	struct { struct lb4_key key; struct lb4_service value; } services[] = {
		/* Nodeport on HOST_IP */
		SVC_KEY_VALUE(0, NODEPORT_EXISTS, SVC_FLAG_NODEPORT, 0),
		SVC_KEY_VALUE(HOST_IP, NODEPORT_EXISTS, SVC_FLAG_NODEPORT, 0),

		/* Hostport on HOST_IP */
		SVC_KEY_VALUE(0, HOSTPORT_EXISTS, SVC_FLAG_HOSTPORT, 0),
		SVC_KEY_VALUE(HOST_IP, HOSTPORT_EXISTS, SVC_FLAG_HOSTPORT, 0),

		/* Hostport on 127.0.0.1 */
		SVC_KEY_VALUE(0, HOSTPORT_EXISTS_LOCALHOST, SVC_FLAG_HOSTPORT, SVC_FLAG_LOOPBACK),
	};
	unsigned long i;

	cache_key.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32);
	cache_key.family = ENDPOINT_KEY_IPV4;
	cache_key.ip4 = bpf_htonl(HOST_IP);
	cache_value.sec_identity = HOST_ID;
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	for (i = 0; i < ARRAY_SIZE(services); i++)
		map_update_elem(&LB4_SERVICES_MAP_V2, &services[i].key, &services[i].value,
				BPF_ANY);
}

CHECK("xdp", "sock4_wildcard_lookup_test")
int test_v4_check(__maybe_unused struct xdp_md *ctx)
{
	struct remote_endpoint_info *info;
	struct lb4_service *ret;
	struct lb4_key key = {
		.address = 0,		/* will set for individual tests */
		.dport = 0,		/* will set for individual tests */
		.proto = 0,		/* nobody cares about L4 type */
		.backend_slot = 0,	/* used internally by lb4_lookup_service */
		.scope = 0,		/* used internally */
	};

	__setup_v4();

	test_init();

	TEST("setup", {
		info = ipcache_lookup4(&IPCACHE_MAP, bpf_htonl(HOST_IP), V4_CACHE_KEY_LEN, 0);
		assert(info);
	});

	TEST("bad-port-range", {
		/* fail: dport is out of nodeport range, but we want a nodeport */
		key.dport = bpf_htons(123);
		ret = sock4_wildcard_lookup(&key, DONT_CARE(0), NODEPORT_LOOKUP, DONT_CARE(0));
		assert(!ret);

		/* fail: dport is inside the nodeport range, but we want a hostport */
		key.dport = bpf_htons((NODEPORT_PORT_MIN + NODEPORT_PORT_MAX) / 2);
		ret = sock4_wildcard_lookup(&key, DONT_CARE(0), HOSTPORT_LOOKUP, DONT_CARE(0));
		assert(!ret);
	});

	TEST("nodeport", {
		/* pass: get a service by loopback address [we're in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock4_wildcard_lookup(&key, DONT_CARE(0), NODEPORT_LOOKUP, HOST_NS);
		assert(ret);

		/* fail: get a service by loopback address [we're not in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock4_wildcard_lookup(&key, DONT_CARE(0), NODEPORT_LOOKUP, OTHER_NS);
		assert(!ret);

		/* pass: get a service by host address [we're in the root namespace] */
		key.address = bpf_htonl(HOST_IP);
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock4_wildcard_lookup(&key, DONT_CARE(0), NODEPORT_LOOKUP, HOST_NS);
		assert(ret);

		/* fail: get a service by host address [we're not in the root namespace] */
		key.address = bpf_htonl(HOST_IP);
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock4_wildcard_lookup(&key, DONT_CARE(0), NODEPORT_LOOKUP, OTHER_NS);
		assert(ret);
	});

	TEST("hostport", {
		/* pass: get a service by loopback address [we're in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock4_wildcard_lookup(&key, DONT_CARE(0), HOSTPORT_LOOKUP, HOST_NS);
		assert(ret);

		/* fail: get a service by loopback address [we're not in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock4_wildcard_lookup(&key, DONT_CARE(0), HOSTPORT_LOOKUP, OTHER_NS);
		assert(!ret);

		/* pass: get a service by loopback address [we're in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock4_wildcard_lookup(&key, DONT_CARE(0), HOSTPORT_LOOKUP, HOST_NS);
		assert(ret);

		/* fail: get a service by loopback address [we're not in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock4_wildcard_lookup(&key, DONT_CARE(0), HOSTPORT_LOOKUP, OTHER_NS);
		assert(!ret);
	});

	/* full wildcard lookups */

	TEST("nodeport-full", {
		/* pass: get a service by loopback address [we're in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock4_wildcard_lookup_full(&key, HOST_NS);
		assert(ret);

		/* fail: get a service by loopback address [we're not in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock4_wildcard_lookup_full(&key, OTHER_NS);
		assert(!ret);

		/* pass: get a service by host address [we're in the root namespace] */
		key.address = bpf_htonl(HOST_IP);
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock4_wildcard_lookup_full(&key, HOST_NS);
		assert(ret);

		/* pass: get a service by host address [we're in the root namespace] */
		key.address = bpf_htonl(HOST_IP);
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock4_wildcard_lookup_full(&key, OTHER_NS);
		assert(ret);
	});

	TEST("hostport-full", {
		/* pass: get a service by loopback address [we're in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock4_wildcard_lookup_full(&key, HOST_NS);
		assert(ret);

		/* fail: get a service by loopback address [we're not in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock4_wildcard_lookup_full(&key, OTHER_NS);
		assert(!ret);

		/* pass: get a service by host address [we're in the root namespace] */
		key.address = bpf_htonl(HOST_IP);
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock4_wildcard_lookup_full(&key, HOST_NS);
		assert(ret);

		/* pass: get a service by host address [we're not in the root namespace] */
		key.address = bpf_htonl(HOST_IP);
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock4_wildcard_lookup_full(&key, OTHER_NS);
		assert(ret);
	});

	TEST("hostport-full-loopback", {
		/* pass: get a loopback service by loopback address [we're in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock4_wildcard_lookup_full(&key, HOST_NS);
		assert(ret);

		/* fail: get a loopback service by loopback address [we're not in the root namespace] */
		key.address = bpf_htonl(INADDR_LOOPBACK);
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock4_wildcard_lookup_full(&key, OTHER_NS);
		assert(!ret);

		/* fail: get a loopback service by host address [we're in the root namespace] */
		key.address = bpf_htonl(HOST_IP);
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock4_wildcard_lookup_full(&key, HOST_NS);
		assert(!ret);

		/* fail: get a loopback service by host address [we're not in the root namespace] */
		key.address = bpf_htonl(HOST_IP);
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock4_wildcard_lookup_full(&key, OTHER_NS);
		assert(!ret);
	});

	test_finish();
}

static inline void __setup_v6_ipcache(const union v6addr *HOST_IP6)
{
	struct remote_endpoint_info cache_value = {};
	struct ipcache_key cache_key = {};

	cache_key.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(128);
	cache_key.family = ENDPOINT_KEY_IPV6;
	cache_key.ip6 = *HOST_IP6;
	cache_value.sec_identity = HOST_ID;
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);
}

static inline void __setup_v6_nodeport(const union v6addr *HOST_IP6)
{
	union v6addr ZERO = {};
	struct { struct lb6_key key; struct lb6_service value; } services[] = {
		/* Nodeport on HOST_IP6 */
		SVC_KEY_VALUE_V6(&ZERO, NODEPORT_EXISTS, SVC_FLAG_NODEPORT, 0),
		SVC_KEY_VALUE_V6(HOST_IP6, NODEPORT_EXISTS, SVC_FLAG_NODEPORT, 0),
	};
	unsigned long i;

	for (i = 0; i < ARRAY_SIZE(services); i++)
		map_update_elem(&LB6_SERVICES_MAP_V2, &services[i].key, &services[i].value,
				BPF_ANY);
}

static inline void __setup_v6_hostport(const union v6addr *HOST_IP6)
{
	union v6addr ZERO = {};
	struct { struct lb6_key key; struct lb6_service value; } services[] = {
		/* Hostport on HOST_IP6 */
		SVC_KEY_VALUE_V6(&ZERO, HOSTPORT_EXISTS, SVC_FLAG_HOSTPORT, 0),
		SVC_KEY_VALUE_V6(HOST_IP6, HOSTPORT_EXISTS, SVC_FLAG_HOSTPORT, 0),

		/* Hostport on ::1 */
		SVC_KEY_VALUE_V6(&ZERO, HOSTPORT_EXISTS_LOCALHOST,
				 SVC_FLAG_HOSTPORT, SVC_FLAG_LOOPBACK),
	};
	unsigned long i;

	for (i = 0; i < ARRAY_SIZE(services); i++)
		map_update_elem(&LB6_SERVICES_MAP_V2, &services[i].key, &services[i].value,
				BPF_ANY);
}

CHECK("xdp", "sock6_wildcard_lookup_test")
int test_v6_check(__maybe_unused struct xdp_md *ctx)
{
	struct remote_endpoint_info *info;
	struct lb6_service *ret;
	struct lb6_key key = {
		.address = {},		/* will set for individual tests */
		.dport = 0,		/* will set for individual tests */
		.proto = 0,		/* nobody cares about L4 type */
		.backend_slot = 0,	/* used internally by lb4_lookup_service */
		.scope = 0,		/* used internally */
	};
	union v6addr HOST_IP6 = {
		.addr = {1, 2, 3, 4, 5, 6, 7, 8, 9 },
	};
	union v6addr LOOPBACK = { .addr[15] = 1, };

	/*
	 * Split to multiple functions, as we are using stack to init values,
	 * and it doesn't fit inside one function
	 */
	__setup_v6_ipcache(&HOST_IP6);
	__setup_v6_nodeport(&HOST_IP6);
	__setup_v6_hostport(&HOST_IP6);

	test_init();

	TEST("setup", {
		info = ipcache_lookup6(&IPCACHE_MAP, &HOST_IP6, V6_CACHE_KEY_LEN, 0);
		assert(info);
	});

	TEST("bad-port-range", {
		/* fail: dport is out of nodeport range, but we want a nodeport */
		key.dport = bpf_htons(123);
		ret = sock6_wildcard_lookup(&key, DONT_CARE(0), NODEPORT_LOOKUP, DONT_CARE(0));
		assert(!ret);

		/* fail: dport is inside the nodeport range, but we want a hostport */
		key.dport = bpf_htons((NODEPORT_PORT_MIN + NODEPORT_PORT_MAX) / 2);
		ret = sock6_wildcard_lookup(&key, DONT_CARE(0), HOSTPORT_LOOKUP, DONT_CARE(0));
		assert(!ret);
	});

	TEST("nodeport", {
		/* pass: get a service by loopback address [we're in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock6_wildcard_lookup(&key, DONT_CARE(0), NODEPORT_LOOKUP, HOST_NS);
		assert(ret);

		/* fail: get a service by loopback address [we're not in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock6_wildcard_lookup(&key, DONT_CARE(0), NODEPORT_LOOKUP, OTHER_NS);
		assert(!ret);

		/* pass: get a service by host address [we're in the root namespace] */
		memcpy(&key.address, &HOST_IP6, sizeof(HOST_IP6));
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock6_wildcard_lookup(&key, DONT_CARE(0), NODEPORT_LOOKUP, HOST_NS);
		assert(ret);

		/* fail: get a service by host address [we're not in the root namespace] */
		memcpy(&key.address, &HOST_IP6, sizeof(HOST_IP6));
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock6_wildcard_lookup(&key, DONT_CARE(0), NODEPORT_LOOKUP, OTHER_NS);
		assert(ret);
	});

	TEST("hostport", {
		/* pass: get a service by loopback address [we're in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock6_wildcard_lookup(&key, DONT_CARE(0), HOSTPORT_LOOKUP, HOST_NS);
		assert(ret);

		/* fail: get a service by loopback address [we're not in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock6_wildcard_lookup(&key, DONT_CARE(0), HOSTPORT_LOOKUP, OTHER_NS);
		assert(!ret);

		/* pass: get a service by loopback address [we're in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock6_wildcard_lookup(&key, DONT_CARE(0), HOSTPORT_LOOKUP, HOST_NS);
		assert(ret);

		/* fail: get a service by loopback address [we're not in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock6_wildcard_lookup(&key, DONT_CARE(0), HOSTPORT_LOOKUP, OTHER_NS);
		assert(!ret);
	});

	/* full wildcard lookups */

	TEST("nodeport-full", {
		/* pass: get a service by loopback address [we're in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock6_wildcard_lookup_full(&key, HOST_NS);
		assert(ret);

		/* fail: get a service by loopback address [we're not in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock6_wildcard_lookup_full(&key, OTHER_NS);
		assert(!ret);

		/* pass: get a service by host address [we're in the root namespace] */
		memcpy(&key.address, &HOST_IP6, sizeof(HOST_IP6));
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock6_wildcard_lookup_full(&key, HOST_NS);
		assert(ret);

		/* pass: get a service by host address [we're in the root namespace] */
		memcpy(&key.address, &HOST_IP6, sizeof(HOST_IP6));
		key.dport = bpf_htons(NODEPORT_EXISTS);
		ret = sock6_wildcard_lookup_full(&key, OTHER_NS);
		assert(ret);
	});

	TEST("hostport-full", {
		/* pass: get a service by loopback address [we're in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock6_wildcard_lookup_full(&key, HOST_NS);
		assert(ret);

		/* fail: get a service by loopback address [we're not in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock6_wildcard_lookup_full(&key, OTHER_NS);
		assert(!ret);

		/* pass: get a service by host address [we're in the root namespace] */
		memcpy(&key.address, &HOST_IP6, sizeof(HOST_IP6));
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock6_wildcard_lookup_full(&key, HOST_NS);
		assert(ret);

		/* pass: get a service by host address [we're not in the root namespace] */
		memcpy(&key.address, &HOST_IP6, sizeof(HOST_IP6));
		key.dport = bpf_htons(HOSTPORT_EXISTS);
		ret = sock6_wildcard_lookup_full(&key, OTHER_NS);
		assert(ret);
	});

	TEST("hostport-full-loopback", {
		/* pass: get a loopback service by loopback address [we're in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock6_wildcard_lookup_full(&key, HOST_NS);
		assert(ret);

		/* fail: get a loopback service by loopback address [we're not in the root namespace] */
		memcpy(&key.address, &LOOPBACK, sizeof(LOOPBACK));
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock6_wildcard_lookup_full(&key, OTHER_NS);
		assert(!ret);

		/* fail: get a loopback service by host address [we're in the root namespace] */
		memcpy(&key.address, &HOST_IP6, sizeof(HOST_IP6));
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock6_wildcard_lookup_full(&key, HOST_NS);
		assert(!ret);

		/* fail: get a loopback service by host address [we're not in the root namespace] */
		memcpy(&key.address, &HOST_IP6, sizeof(HOST_IP6));
		key.dport = bpf_htons(HOSTPORT_EXISTS_LOCALHOST);
		ret = sock6_wildcard_lookup_full(&key, OTHER_NS);
		assert(!ret);
	});

	test_finish();
}
