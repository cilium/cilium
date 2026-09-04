// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Drives the from-host encap path that CI tripped over and inspects the
 * bpf_tunnel_key the datapath hands to the kernel.
 *
 * cil_from_host resolves the source identity from the ipcache
 * (resolve_srcid_ipv4), so external traffic carries whatever local identity the
 * agent allocated for the source address, and hands it to
 * encap_and_redirect_with_nodeid -> ctx_set_encap_info4 ->
 * key.tunnel_id = get_tunnel_id(seclabel) -> skb_set_tunnel_key.
 *
 * The tunnel id ends up in the VXLAN/Geneve VNI, which is 24 bits wide, so a
 * node-local identity loses its scope byte. 0x01000001, the first local
 * identity a node allocates, arrives as 1 == HOST_ID and cil_from_overlay
 * drops it with DROP_INVALID_IDENTITY.
 *
 * The 5-tuple is the one from the CI sysdump: an egress gateway reply,
 * 172.20.0.3:8194 -> 10.244.1.165:48368, FIN+ACK.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Datapath configuration: VXLAN tunneling, dual stack as in the CI cluster. */
#define ENCAP_IFINDEX 1
#define ENABLE_IPV4
#define ENABLE_IPV6
#define TUNNEL_MODE

#define SRC_MAC mac_one
#define DST_MAC mac_two
#define SRC_IPV4 IPV4(172, 20, 0, 3)
#define DST_IPV4 IPV4(10, 244, 1, 165)
#define SRC_TCP_PORT __bpf_htons(8194)
#define DST_TCP_PORT __bpf_htons(48368)

#define DST_IDENTITY 1230

/* Record what the datapath passes to skb_set_tunnel_key. The map holds the
 * whole key so the check can look at the tunnel endpoint too.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_tunnel_key));
	__uint(max_entries, 1);
} tunnel_key_map __section_maps_btf;

bool tunnel_key_set;

#define skb_set_tunnel_key mock_skb_set_tunnel_key
static __always_inline int
mock_skb_set_tunnel_key(__maybe_unused struct __sk_buff *skb,
			const struct bpf_tunnel_key *from,
			__maybe_unused __u32 size,
			__maybe_unused __u32 flags)
{
	__u32 map_key = 0;
	struct bpf_tunnel_key *mock_key = map_lookup_elem(&tunnel_key_map, &map_key);

	if (mock_key) {
		memcpy(mock_key, from, sizeof(*mock_key));
		tunnel_key_set = true;
	}

	return 0;
}

#include "lib/bpf_host.h"
#include "lib/ipcache.h"

/* Hybrid routing would send the packet out without a tunnel. */
ASSIGN_CONFIG(bool, hybrid_routing_enabled, false)

static __always_inline int
pktgen_from_host(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
					  SRC_IPV4, DST_IPV4,
					  SRC_TCP_PORT, DST_TCP_PORT);
	if (!l4)
		return TEST_ERROR;

	/* The CI packet was a FIN+ACK. */
	l4->syn = 0;
	l4->fin = 1;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
setup(struct __ctx_buff *ctx, __u32 src_identity)
{
	/* The source is external, so the agent holds a node-local identity for
	 * it and no tunnel endpoint.
	 */
	ipcache_v4_add_entry(SRC_IPV4, 0, src_identity, 0, 0);

	/* The destination is a pod on another node, reached through a tunnel. */
	ipcache_v4_add_entry(DST_IPV4, 0, DST_IDENTITY, v4_node_two, 0);

	return host_send_packet(ctx);
}

static __always_inline int
check_tunnel_key(const struct __ctx_buff *ctx, __u32 expected_id)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	__u32 map_key = 0;
	struct bpf_tunnel_key *key;
	__u32 tunnel_id;
	__be32 vni;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* The packet has to have been encapsulated, otherwise there is no
	 * tunnel key to look at and the rest of the test is vacuous.
	 */
	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("not encapsulated, status %lu", *status_code);

	if (!tunnel_key_set)
		test_fatal("skb_set_tunnel_key not called");

	key = map_lookup_elem(&tunnel_key_map, &map_key);
	if (!key)
		test_fatal("no tunnel key recorded");

	if (key->remote_ipv4 != bpf_ntohl(v4_node_two))
		test_fatal("wrong tunnel ep %lx", key->remote_ipv4);

	tunnel_id = key->tunnel_id;

	/* The kernel copies the low 24 bits of the tunnel id into the VNI, and
	 * cilium decodes the VNI back with tunnel_vni_to_sec_identity(). An id
	 * that does not survive that round trip reaches the peer as a
	 * different identity.
	 */
	vni = sec_identity_to_tunnel_vni(tunnel_id);

	if (tunnel_vni_to_sec_identity(vni) != tunnel_id)
		test_fatal("id %lx arrives as %lx", tunnel_id,
			   tunnel_vni_to_sec_identity(vni));

	/* The same statement without the encoding: the scope byte has to be
	 * gone before the id is handed to the kernel.
	 */
	if (identity_is_local(tunnel_id))
		test_fatal("local id %lx in tunnel key", tunnel_id);

	if (tunnel_id != expected_id)
		test_fatal("tunnel id %lx, want %lx", tunnel_id, expected_id);

	test_finish();
}

/* The identity from the CI failure, 16777217. It used to reach the peer as
 * HOST_ID, which cil_from_overlay rejects with DROP_INVALID_IDENTITY.
 */
PKTGEN(PROG_TYPE, "01_cidr_scope_source")
int cidr_scope_source_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx);
}

SETUP(PROG_TYPE, "01_cidr_scope_source")
int cidr_scope_source_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, IDENTITY_LOCAL_SCOPE_CIDR | 1);
}

CHECK(PROG_TYPE, "01_cidr_scope_source")
int cidr_scope_source_check(const struct __ctx_buff *ctx)
{
	return check_tunnel_key(ctx, WORLD_ID);
}

/* A remote node scope source used to arrive as KUBE_APISERVER_NODE_ID. */
PKTGEN(PROG_TYPE, "02_remote_node_scope_source")
int remote_node_scope_source_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_host(ctx);
}

SETUP(PROG_TYPE, "02_remote_node_scope_source")
int remote_node_scope_source_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, IDENTITY_LOCAL_SCOPE_REMOTE_NODE | 7);
}

CHECK(PROG_TYPE, "02_remote_node_scope_source")
int remote_node_scope_source_check(const struct __ctx_buff *ctx)
{
	return check_tunnel_key(ctx, REMOTE_NODE_ID);
}
