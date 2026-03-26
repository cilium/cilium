// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "encryption_helpers_ipsec.h"

#include "lib/bpf_host.h"

#include "node_config.h"

#include "tests/lib/ipcache.h"
#include "tests/lib/ipsec.h"
#include "tests/lib/node.h"

static __always_inline
void set_src_identity(bool ipv4_inner, bool ipv4_outer, __u32 identity)
{
	if (ipv4_inner)
		if (ipv4_outer)
			ipcache_v4_add_entry(SOURCE_IP, 0, identity, SOURCE_NODE_IP, BAD_SPI);
		else
			ipcache_v4_add_entry_ipv6_underlay(SOURCE_IP, 0, identity,
							   (const union v6addr *)SOURCE_NODE_IP_6,
							   BAD_SPI);
	else
		if (ipv4_outer)
			ipcache_v6_add_entry((const union v6addr *)SOURCE_IP_6, 0,
					     identity, SOURCE_NODE_IP, BAD_SPI);
		else
			ipcache_v6_add_entry_ipv6_underlay((const union v6addr *)SOURCE_IP_6, 0,
							   identity,
							   (const union v6addr *)SOURCE_NODE_IP_6,
							   BAD_SPI);
}

static __always_inline
void set_dst_identity(bool ipv4_inner, bool ipv4_outer, __u32 identity, __u8 spi)
{
	if (ipv4_inner)
		if (ipv4_outer)
			ipcache_v4_add_entry(DST_IP, 0, identity, DST_NODE_IP, spi);
		else
			ipcache_v4_add_entry_ipv6_underlay(DST_IP, 0, identity,
							   (const union v6addr *)DST_NODE_IP_6,
							   spi);
	else
		if (ipv4_outer)
			ipcache_v6_add_entry((const union v6addr *)DST_IP_6, 0,
					     identity, DST_NODE_IP, spi);
		else
			ipcache_v6_add_entry_ipv6_underlay((const union v6addr *)DST_IP_6, 0,
							   identity,
							   (const union v6addr *)DST_NODE_IP_6,
							   spi);
}

static __always_inline
int ipsec_redirect_checks(const struct __ctx_buff *ctx, bool ipv4_inner, bool ipv4_outer)
{
	test_init();

	__be16 proto = ctx_get_protocol(ctx);
	int ret = 0;

	if (ipv4_outer)
		node_v4_add_entry(DST_NODE_IP, DST_NODE_ID, TARGET_SPI);
	else
		node_v6_add_entry((const union v6addr *)DST_NODE_IP_6,
				  DST_NODE_ID, TARGET_SPI);

	ipsec_set_encrypt_state(BAD_SPI);

	set_src_identity(ipv4_inner, ipv4_outer, SOURCE_IDENTITY);
	set_dst_identity(ipv4_inner, ipv4_outer, DST_IDENTITY, TARGET_SPI);

	TEST("pod-to-pod", {
		ret = ipsec_maybe_redirect_to_encrypt((struct __ctx_buff *)ctx,
						      proto, SOURCE_IDENTITY);
		assert(ret == CTX_ACT_REDIRECT);
	});

	test_finish();
}

static __always_inline
int bad_identities_check(struct __ctx_buff *ctx, bool is_ipv4)
{
	test_init();

	int ret = 0;
	__be16 proto = is_ipv4 ? bpf_htons(ETH_P_IP) : bpf_htons(ETH_P_IPV6);

	ipsec_set_encrypt_state(BAD_SPI);

	/*
	 * Ensure host-to-pod traffic is not encrypted.
	 */
	TEST("native-host-to-pod", {
		set_dst_identity(is_ipv4, true, DST_IDENTITY, TARGET_SPI);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, HOST_ID);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure world-to-pod traffic is not encrypted.
	 */
	TEST("native-world-to-pod", {
		set_dst_identity(is_ipv4, true, DST_IDENTITY, TARGET_SPI);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, WORLD_ID);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure remote_node-to-pod traffic is not encrypted.
	 */
	TEST("native-remote_node-to-pod", {
		set_dst_identity(is_ipv4, true, DST_IDENTITY, TARGET_SPI);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, REMOTE_NODE_ID);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure pod-to-host traffic is not encrypted.
	 */
	TEST("native-pod-to-host", {
		set_dst_identity(is_ipv4, true, HOST_ID, 0);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, SOURCE_IDENTITY);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure pod-to-world traffic is not encrypted.
	 */
	TEST("native-pod-to-world", {
		set_dst_identity(is_ipv4, true, WORLD_ID, 0);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, SOURCE_IDENTITY);
		assert(ret == CTX_ACT_OK);
	})

	/*
	 * Ensure pod-to-remote_node traffic is not encrypted.
	 */
	TEST("native-pod-to-remote_node", {
		set_dst_identity(is_ipv4, true, REMOTE_NODE_ID, 0);
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

CHECK("tc", "ipsec_redirect4")
int ipsec_redirect4_check(struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx, true, true);
}

PKTGEN("tc", "ipsec_redirect4_over6")
int ipsec_redirect4_over6_pktgen(struct __ctx_buff *ctx)
{
	return generate_native_packet(ctx, true);
}

CHECK("tc", "ipsec_redirect4_over6")
int ipsec_redirect4_over6_check(struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx, true, false);
}

PKTGEN("tc", "ipsec_redirect6")
int ipsec_redirect6_pktgen(struct __ctx_buff *ctx)
{
	return generate_native_packet(ctx, false);
}

CHECK("tc", "ipsec_redirect6")
int ipsec_redirect6_check(struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx, false, true);
}

PKTGEN("tc", "ipsec_redirect6_over6")
int ipsec_redirect6_over6_pktgen(struct __ctx_buff *ctx)
{
	return generate_native_packet(ctx, false);
}

CHECK("tc", "ipsec_redirect6_over6")
int ipsec_redirect6_over6_check(struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx, false, false);
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
