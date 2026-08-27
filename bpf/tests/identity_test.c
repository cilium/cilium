// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Both families are needed, otherwise WORLD_IPV4_ID and WORLD_IPV6_ID collapse
 * to WORLD_ID and the branches under test are compiled out.
 */
#define ENABLE_IPV4
#define ENABLE_IPV6

#include <bpf/ctx/xdp.h>
#include "common.h"
#include <bpf/config/node.h>

#include <lib/identity.h>

/* Width of the VXLAN/Geneve VNI, which is what overloadable_{skb,xdp}.h store
 * the tunnel id in.
 */
#define VNI_MASK 0x00ffffffU

/* The identity as the peer reads it back out of the tunnel header. */
static __always_inline __u32 on_the_wire(__u32 identity)
{
	return get_tunnel_id(identity) & VNI_MASK;
}

/* Tables live at file scope because TEST() is a two argument macro: a brace
 * initializer inside its body would be split on its commas.
 */
static const __u32 scopes[] = {
	0,
	IDENTITY_LOCAL_SCOPE_CIDR,
	IDENTITY_LOCAL_SCOPE_REMOTE_NODE,
	0x03000000, /* unallocated today */
	0x7f000000,
	IDENTITY_LOCAL_SCOPE_MASK,
};

static const __u32 low[] = {
	0, HOST_ID, WORLD_ID, UNMANAGED_ID, HEALTH_ID, INIT_ID,
	REMOTE_NODE_ID, KUBE_APISERVER_NODE_ID, INGRESS_ID,
	WORLD_IPV4_ID, WORLD_IPV6_ID,
	100, 400, 0xaabb, 0xffff, 0x00010000, 0x0001aabb,
	VNI_MASK,
};

static const __u32 global_ids[] = {
	HOST_ID, HEALTH_ID, REMOTE_NODE_ID, KUBE_APISERVER_NODE_ID,
	INGRESS_ID, 400, 0x0001aabb,
};

CHECK(PROG_TYPE, "get_tunnel_id")
int bpf_test_get_tunnel_id(__maybe_unused struct xdp_md *ctx)
{
	test_init();

	TEST("pass-through", {
		assert(get_tunnel_id(HOST_ID) == HOST_ID);
		assert(get_tunnel_id(WORLD_ID) == WORLD_ID);
		assert(get_tunnel_id(HEALTH_ID) == HEALTH_ID);
		assert(get_tunnel_id(REMOTE_NODE_ID) == REMOTE_NODE_ID);
		assert(get_tunnel_id(KUBE_APISERVER_NODE_ID) == KUBE_APISERVER_NODE_ID);
		assert(get_tunnel_id(INGRESS_ID) == INGRESS_ID);
		assert(get_tunnel_id(400) == 400);

		/* cluster 1, endpoint 0xaabb */
		assert(get_tunnel_id(0x0001aabb) == 0x0001aabb);
		/* the largest identity that still fits in the VNI */
		assert(get_tunnel_id(VNI_MASK) == VNI_MASK);
	});

	TEST("world-ipv4-ipv6", {
		assert(get_tunnel_id(WORLD_IPV4_ID) == WORLD_ID);
		assert(get_tunnel_id(WORLD_IPV6_ID) == WORLD_ID);
	});

	/* The first local identity a node allocates used to reach the peer as
	 * HOST_ID, which cil_from_overlay rejects with DROP_INVALID_IDENTITY.
	 */
	TEST("cidr-scope-identity", {
		__u32 id = IDENTITY_LOCAL_SCOPE_CIDR | 1; /* 16777217 */

		assert(get_tunnel_id(id) == WORLD_ID);
		assert(on_the_wire(id) == get_tunnel_id(id));
		assert(on_the_wire(id) != HOST_ID);
	});

	/* Truncation does not only drop, it aliases: left as is, these three
	 * arrive as REMOTE_NODE_ID, WORLD_ID and INGRESS_ID.
	 */
	TEST("cidr-scope-identity-aliasing", {
		__u32 alias_node = IDENTITY_LOCAL_SCOPE_CIDR | REMOTE_NODE_ID;
		__u32 alias_world = IDENTITY_LOCAL_SCOPE_CIDR | WORLD_ID;
		__u32 alias_ingress = IDENTITY_LOCAL_SCOPE_CIDR | INGRESS_ID;

		assert(get_tunnel_id(alias_node) == WORLD_ID);
		assert(on_the_wire(alias_node) == WORLD_ID);
		assert(!identity_is_remote_node(on_the_wire(alias_node)));

		assert(get_tunnel_id(alias_world) == WORLD_ID);
		assert(on_the_wire(alias_world) == WORLD_ID);

		assert(get_tunnel_id(alias_ingress) == WORLD_ID);
		assert(on_the_wire(alias_ingress) == WORLD_ID);
		assert(!identity_is_ingress(on_the_wire(alias_ingress)));
	});

	TEST("remote-node-scope-identity", {
		__u32 id = IDENTITY_LOCAL_SCOPE_REMOTE_NODE | 7;

		assert(get_tunnel_id(IDENTITY_LOCAL_SCOPE_REMOTE_NODE) == REMOTE_NODE_ID);
		assert(get_tunnel_id(id) == REMOTE_NODE_ID);
		assert(on_the_wire(id) == get_tunnel_id(id));
		assert(identity_is_remote_node(on_the_wire(id)));
	});

	/* The invariant rather than the examples: whatever comes out has to fit
	 * in the VNI, including for scopes that do not exist yet.
	 */
	TEST("fits-in-vni", {
		__u32 bad_in = 0;
		__u32 bad_out = 0;
		__u32 i;
		__u32 j;

		for (i = 0; i < ARRAY_SIZE(scopes); i++) {
			for (j = 0; j < ARRAY_SIZE(low); j++) {
				__u32 id = scopes[i] | low[j];
				__u32 tunnel_id = get_tunnel_id(id);

				if (identity_is_local(tunnel_id) && !bad_out) {
					bad_in = id;
					bad_out = tunnel_id;
				}
			}
		}

		if (bad_out)
			test_fatal("id %lx became %lx", bad_in, bad_out);
	});

	test_finish();
}

CHECK(PROG_TYPE, "get_id_from_tunnel_id")
int bpf_test_get_id_from_tunnel_id(__maybe_unused struct xdp_md *ctx)
{
	__be16 v4 = bpf_htons(ETH_P_IP);
	__be16 v6 = bpf_htons(ETH_P_IPV6);

	test_init();

	TEST("world-round-trip", {
		assert(get_id_from_tunnel_id(get_tunnel_id(WORLD_IPV4_ID), v4) == WORLD_IPV4_ID);
		assert(get_id_from_tunnel_id(get_tunnel_id(WORLD_IPV6_ID), v6) == WORLD_IPV6_ID);

		/* a CIDR scope identity degrades to the world identity of the
		 * family the packet carries
		 */
		assert(get_id_from_tunnel_id(get_tunnel_id(IDENTITY_LOCAL_SCOPE_CIDR | 1), v4) ==
		       WORLD_IPV4_ID);
		assert(get_id_from_tunnel_id(get_tunnel_id(IDENTITY_LOCAL_SCOPE_CIDR | 1), v6) ==
		       WORLD_IPV6_ID);
	});

	TEST("identity-round-trip", {
		__u32 i;

		for (i = 0; i < ARRAY_SIZE(global_ids); i++) {
			__u32 id = global_ids[i];

			if (get_id_from_tunnel_id(get_tunnel_id(id), v4) != id)
				test_fatal("id %lx broke over IPv4", id);
			if (get_id_from_tunnel_id(get_tunnel_id(id), v6) != id)
				test_fatal("id %lx broke over IPv6", id);
		}
	});

	TEST("remote-node-round-trip", {
		__u32 id = IDENTITY_LOCAL_SCOPE_REMOTE_NODE | 7;

		assert(get_id_from_tunnel_id(get_tunnel_id(id), v4) == REMOTE_NODE_ID);
		assert(get_id_from_tunnel_id(get_tunnel_id(id), v6) == REMOTE_NODE_ID);
	});

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
