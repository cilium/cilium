// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "ipsec_redirect_generic.h"

#include "node_config.h"
#include "lib/encrypt.h"
#include "tests/lib/ipcache.h"
#include "tests/lib/node.h"

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
int ipsec_redirect_checks(__maybe_unused struct __ctx_buff *ctx, bool is_ipv4)
{
	test_init();

	int ret = 0;
	__be16 proto = is_ipv4 ? bpf_htons(ETH_P_IP) : bpf_htons(ETH_P_IPV6);

	if (is_ipv4)
		node_v4_add_entry(DST_NODE_IP, DST_NODE_ID, TARGET_SPI);
	else
		node_v6_add_entry((const union v6addr *)DST_NODE_IP_6, DST_NODE_ID, TARGET_SPI);

	/* fill encrypt map with node's current SPI 3 */
	struct encrypt_config cfg = {
		.encrypt_key = BAD_SPI,
	};
	map_update_elem(&cilium_encrypt_state, &ret, &cfg, BPF_ANY);

	/*
	 * Set destination identity for DST_IP / DST_IP_6.
	 * There is no need to set also for the source, as it is passed as
	 * parameter to `ipsec_maybe_redirect_to_encrypt`.
	 */
	set_dst_identity(is_ipv4, DST_IDENTITY);

	ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, SOURCE_IDENTITY);
	assert(ret == CTX_ACT_REDIRECT);

	/* assert we set the correct mark */
	assert(ctx->mark == ipsec_encode_encryption_mark(TARGET_SPI, DST_NODE_ID));

	/* the original source layer 2 address should be the destination for
	 * hairpin redirect
	 */
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(struct ethhdr) > data_end)
		test_fatal("packet too small for eth header");

	struct ethhdr *l2 = data;
	int i;

	for (i = 0; i < 6; i++)
		assert(l2->h_dest[i] = SOURCE_MAC[i]);

	/* ctx_redirect should be called with INGRESS flag for hairpin redirect
	 */
	assert(rec.flags == BPF_F_INGRESS);

	test_finish();
}

static __always_inline
int bad_identities_check(__maybe_unused struct __ctx_buff *ctx, bool is_ipv4)
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

PKTGEN("tc", "ipsec_redirect")
int ipsec_redirect_pktgen(struct __ctx_buff *ctx)
{
	return generate_native_packet(ctx, true);
}

CHECK("tc", "ipsec_redirect")
int ipsec_redirect_check(__maybe_unused struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx, true);
}

PKTGEN("tc", "ipsec_redirect6")
int ipsec_redirect6_pktgen(struct __ctx_buff *ctx)
{
	return generate_native_packet(ctx, false);
}

CHECK("tc", "ipsec_redirect6")
int ipsec_redirect6_check(__maybe_unused struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx, false);
}

PKTGEN("tc", "ipsec_redirect_bad_identities")
int ipsec_redirect_bad_identities_pktgen(struct __ctx_buff *ctx)
{
	return generate_native_packet(ctx, true);
}

CHECK("tc", "ipsec_redirect_bad_identities")
int ipsec_redirect_bad_identities_check(__maybe_unused struct __ctx_buff *ctx)
{
	return bad_identities_check(ctx, true);
}

PKTGEN("tc", "ipsec_redirect_bad_identities6")
int ipsec_redirect_bad_identities6_pktgen(struct __ctx_buff *ctx)
{
	return generate_native_packet(ctx, false);
}

CHECK("tc", "ipsec_redirect_bad_identities6")
int ipsec_redirect_bad_identities6_check(__maybe_unused struct __ctx_buff *ctx)
{
	return bad_identities_check(ctx, false);
}
