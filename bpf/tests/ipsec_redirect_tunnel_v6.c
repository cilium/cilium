// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define TUNNEL_MODE

#include "ipsec_redirect_generic.h"

#include "node_config.h"

/* must define `HAVE_ENCAP 1` before including 'lib/encrypt.h'.
 * lib/encrypt.h eventually imports overloadable_skb.h which exposes
 * ctx_is_overlay and ctx_is_overlay_encrypted, utilized within
 * 'ipsec_maybe_redirect_to_encrypt'
 */
#define HAVE_ENCAP 1
#include "lib/encrypt.h"

#include "tests/lib/ipcache.h"

PKTGEN("tc", "ipsec_redirect_tunnel_v6_pod_to_pod")
int ipsec_redirect_pktgen_v6_pod_to_pod(struct __ctx_buff *ctx)
{
	return vxlan_ipv6_packet(ctx);
}

CHECK("tc", "ipsec_redirect_tunnel_v6_pod_to_pod")
int ipsec_redirect_check_v6_pod_to_pod(__maybe_unused struct __ctx_buff *ctx) {
	test_init();

	int ret = 0;

	struct node_key key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = DST_NODE_IP,
	};
	struct node_value val = {
		.id = DST_NODE_ID,
		.spi = TARGET_SPI,
	};

	map_update_elem(&NODE_MAP_V2, &key, &val, BPF_ANY);

	struct encrypt_config cfg = {
		.encrypt_key = BAD_SPI,
	};
	map_update_elem(&ENCRYPT_MAP, &ret, &cfg, BPF_ANY);

	/*
	 * Ensure encryption mark is set for pod-to-pod traffic and
	 * CTX_ACT_REDIRECT is set.
	 */
	TEST("overlay-pod-to-pod", {
		/* add dst ipcache entry mapping to inner dst ipv4 */
		ipcache_v6_add_entry((union v6addr *)DST_IP_6,
				     0, DST_IDENTITY, DST_IP, TARGET_SPI);

		ctx->mark = SOURCE_IDENTITY | MARK_MAGIC_OVERLAY;
		/*
		 * NOTE: the passedin SOURCE_IDENTITY does not matter here,
		 * once the function determines the packet is MARK_MAGIC_OVERLAY
		 * it will pull the identity directly from ctx.
		 */
		ret = ipsec_maybe_redirect_to_encrypt(ctx, bpf_htons(ETH_P_IP),
						      SOURCE_IDENTITY);

		assert(ctx->mark == TARGET_MARK);
		assert(ret == CTX_ACT_REDIRECT);
	})

	test_finish();
}

PKTGEN("tc", "ipsec_redirect_tunnel_v6_bad_identities")
int ipsec_redirect_pktgen_v6_bad_identites(struct __ctx_buff *ctx)
{
	return vxlan_ipv6_packet(ctx);
}

CHECK("tc", "ipsec_redirect_tunnel_v6_bad_identities")
int ipsec_redirect_check_v6_bad_identities(__maybe_unused struct __ctx_buff *ctx) {
	test_init();

	int ret = 0;

	/*
	 * Ensure if source identity is HOST_ID encryption does not occur
	 */
	TEST("overlay-host-to-pod", {
		__u32 mark = MARK_MAGIC_OVERLAY | (HOST_ID << 16);
		ctx->mark = mark;
		ret = ipsec_maybe_redirect_to_encrypt(ctx, bpf_htons(ETH_P_IP),
						      SOURCE_IDENTITY);
		assert(ctx->mark == mark);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure if source identity is WORLD_ID encryption does not occur
	 */
	TEST("overlay-world-to-pod", {
		__u32 mark = MARK_MAGIC_OVERLAY | (WORLD_ID << 16);
		ctx->mark = mark;
		ret = ipsec_maybe_redirect_to_encrypt(ctx, bpf_htons(ETH_P_IP),
						      SOURCE_IDENTITY);
		assert(ctx->mark == mark);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure if source identity is REMOTE_NODE_ID encryption does not occur
	 */
	TEST("overlay-remote-node-to-pod", {
		__u32 mark = MARK_MAGIC_OVERLAY | (REMOTE_NODE_ID << 16);
		ctx->mark = mark;
		ret = ipsec_maybe_redirect_to_encrypt(ctx, bpf_htons(ETH_P_IP),
						      SOURCE_IDENTITY);
		assert(ctx->mark == mark);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure if dst identity is HOST_ID encryption does not occur
	 */
	TEST("overlay-pod-to-host", {
		__u32 mark = MARK_MAGIC_OVERLAY | SOURCE_IDENTITY;
		ipcache_v6_add_entry((union v6addr *)DST_IP_6, 0, HOST_ID,
				     DST_IP, TARGET_SPI);

		ctx->mark = mark;
		ret = ipsec_maybe_redirect_to_encrypt(ctx, bpf_htons(ETH_P_IP),
						      SOURCE_IDENTITY);

		assert(ctx->mark == mark);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure if dst identity is WORLD_ID encryption does not occur
	 */
	TEST("overlay-pod-to-world", {
		__u32 mark = MARK_MAGIC_OVERLAY | SOURCE_IDENTITY;
		ipcache_v6_add_entry((union v6addr *)DST_IP_6, 0, WORLD_ID,
				     DST_IP, TARGET_SPI);

		ctx->mark = mark;
		ret = ipsec_maybe_redirect_to_encrypt(ctx, bpf_htons(ETH_P_IP),
						      SOURCE_IDENTITY);

		assert(ctx->mark == mark);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure if dst identity is REMOTE_NODE_ID encryption does not occur
	 */
	TEST("overlay-pod-to-remote_node", {
		__u32 mark = MARK_MAGIC_OVERLAY | SOURCE_IDENTITY;
		ipcache_v6_add_entry((union v6addr *)DST_IP_6, 0, REMOTE_NODE_ID,
				     DST_IP, TARGET_SPI);

		ctx->mark = mark;
		ret = ipsec_maybe_redirect_to_encrypt(ctx, bpf_htons(ETH_P_IP),
						      SOURCE_IDENTITY);

		assert(ctx->mark == mark);
		assert(ret == CTX_ACT_OK);
	})

	test_finish();
}
