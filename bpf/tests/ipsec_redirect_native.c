// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "ipsec_redirect_generic.h"

#include "bpf_host.c"

#include "node_config.h"
#include "lib/encrypt.h"
#include "tests/lib/ipcache.h"
#include "tests/lib/node.h"

#define TO_NETDEV 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
	},
};

static __always_inline
void set_src_identity(bool is_ipv4, __u32 identity)
{
	if (is_ipv4)
		ipcache_v4_add_entry(SOURCE_IP, 0, identity, SOURCE_NODE_IP, BAD_SPI);
	else
		ipcache_v6_add_entry((const union v6addr *)SOURCE_IP_6, 0,
				     identity, SOURCE_NODE_IP, BAD_SPI);
}

static __always_inline
void set_dst_identity(bool is_ipv4, __u32 identity)
{
	if (is_ipv4)
		ipcache_v4_add_entry(DST_IP, 0, identity, DST_NODE_IP, TARGET_SPI);
	else
		ipcache_v6_add_entry((const union v6addr *)DST_IP_6, 0,
				     identity, DST_NODE_IP, TARGET_SPI);
}

static __always_inline
int ipsec_redirect_setup(struct __ctx_buff *ctx, bool is_ipv4)
{
	__u32 encrypt_key = 0;

	/* Setup IPv4 only has we're using a IPv4 tunnel endpoint in all cases. */
	node_v4_add_entry(DST_NODE_IP, DST_NODE_ID, TARGET_SPI);

	/* fill encrypt map with node's current SPI 3 */
	struct encrypt_config cfg = {
		.encrypt_key = BAD_SPI,
	};
	map_update_elem(&cilium_encrypt_state, &encrypt_key, &cfg, BPF_ANY);

	set_src_identity(is_ipv4, SOURCE_IDENTITY);
	set_dst_identity(is_ipv4, DST_IDENTITY);

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

static __always_inline
int ipsec_redirect_checks(const struct __ctx_buff *ctx)
{
	union macaddr expected_l2_addr = CILIUM_NET_MAC;
	__u32 *status_code;
	struct ethhdr *l2;
	int i;

	test_init();

	assert(ctx->mark == ipsec_encode_encryption_mark(TARGET_SPI, DST_NODE_ID));

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	if (data + sizeof(struct ethhdr) > data_end)
		test_fatal("packet too small for eth header");

	l2 = data + sizeof(*status_code);

	for (i = 0; i < 6; i++)
		assert(l2->h_dest[i] == expected_l2_addr.addr[i]);

	/* ctx_redirect should be called with INGRESS flag for hairpin redirect
	 */
	assert(rec.flags == BPF_F_INGRESS);

	test_finish();
}

static __always_inline
int bad_identities_check(struct __ctx_buff *ctx, bool is_ipv4)
{
	test_init();

	int ret = 0;
	__be16 proto = is_ipv4 ? bpf_htons(ETH_P_IP) : bpf_htons(ETH_P_IPV6);

	/* fill encrypt map with node's current SPI 3 */
	struct encrypt_config cfg = {
		.encrypt_key = BAD_SPI,
	};
	map_update_elem(&cilium_encrypt_state, &ret, &cfg, BPF_ANY);

	/*
	 * Ensure host-to-pod traffic is not encrypted.
	 */
	TEST("native-host-to-pod", {
		set_dst_identity(is_ipv4, DST_IDENTITY);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, HOST_ID);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure world-to-pod traffic is not encrypted.
	 */
	TEST("native-world-to-pod", {
		set_dst_identity(is_ipv4, DST_IDENTITY);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, WORLD_ID);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure remote_node-to-pod traffic is not encrypted.
	 */
	TEST("native-remote_node-to-pod", {
		set_dst_identity(is_ipv4, DST_IDENTITY);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, REMOTE_NODE_ID);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure pod-to-host traffic is not encrypted.
	 */
	TEST("native-pod-to-host", {
		set_dst_identity(is_ipv4, HOST_ID);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, SOURCE_IDENTITY);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure pod-to-world traffic is not encrypted.
	 */
	TEST("native-pod-to-world", {
		set_dst_identity(is_ipv4, WORLD_ID);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, SOURCE_IDENTITY);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure pod-to-remote_node traffic is not encrypted.
	 */
	TEST("native-pod-to-remote_node", {
		set_dst_identity(is_ipv4, REMOTE_NODE_ID);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, SOURCE_IDENTITY);
		assert(ret == CTX_ACT_OK);
	})

	test_finish();
}

PKTGEN("tc", "ipsec_redirect4")
int ipsec_redirect4_pktgen(struct __ctx_buff *ctx)
{
	return generate_native_packet(ctx, true);
}

SETUP("tc", "ipsec_redirect4")
int ipsec_redirect4_setup(struct __ctx_buff *ctx)
{
	return ipsec_redirect_setup(ctx, true);
}

CHECK("tc", "ipsec_redirect4")
int ipsec_redirect4_check(struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx);
}

PKTGEN("tc", "ipsec_redirect6")
int ipsec_redirect6_pktgen(struct __ctx_buff *ctx)
{
	return generate_native_packet(ctx, false);
}

SETUP("tc", "ipsec_redirect6")
int ipsec_redirect6_setup(struct __ctx_buff *ctx)
{
	return ipsec_redirect_setup(ctx, false);
}

CHECK("tc", "ipsec_redirect6")
int ipsec_redirect6_check(struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx);
}

PKTGEN("tc", "ipsec_redirect_bad_identities4")
int ipsec_redirect_bad_identities4_pktgen(struct __ctx_buff *ctx)
{
	return generate_native_packet(ctx, true);
}

CHECK("tc", "ipsec_redirect_bad_identities4")
int ipsec_redirect_bad_identities4_check(struct __ctx_buff *ctx)
{
	return bad_identities_check(ctx, true);
}

PKTGEN("tc", "ipsec_redirect_bad_identities6")
int ipsec_redirect_bad_identities6_pktgen(struct __ctx_buff *ctx)
{
	return generate_native_packet(ctx, false);
}

CHECK("tc", "ipsec_redirect_bad_identities6")
int ipsec_redirect_bad_identities6_check(struct __ctx_buff *ctx)
{
	return bad_identities_check(ctx, false);
}
