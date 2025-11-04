// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define TUNNEL_MODE

#include "ipsec_redirect_generic.h"

#include "node_config.h"

/* must define `HAVE_ENCAP 1` before including 'lib/ipsec.h'.
 * lib/ipsec.h eventually imports overloadable_skb.h which exposes
 * ctx_is_overlay, utilized within 'ipsec_maybe_redirect_to_encrypt'
 */
#define HAVE_ENCAP 1
#include "../lib/ipsec.h"

#include "tests/lib/node.h"
#include "tests/lib/ipcache.h"
#include "tests/lib/ipsec.h"

static __always_inline
int ipsec_redirect_checks(__maybe_unused struct __ctx_buff *ctx, bool outer_ipv4)
{
	test_init();

	int ret = 0;
	__be16 proto = outer_ipv4 ? bpf_htons(ETH_P_IP) : bpf_htons(ETH_P_IPV6);

	if (outer_ipv4)
		node_v4_add_entry(DST_NODE_IP, DST_NODE_ID, TARGET_SPI);
	else
		node_v6_add_entry((const union v6addr *)DST_NODE_IP_6, DST_NODE_ID, TARGET_SPI);

	ipsec_set_encrypt_state(BAD_SPI);

	/*
	 * Ensure encryption mark is set for overlay traffic with source
	 * identity pod SOURCE_IDENTITY and CTX_ACT_REDIRECT is set.
	 *
	 * NOTE: with MARK_MAGIC_OVERLAY, any source identity in the ctx->mark
	 * would make `ipsec_maybe_redirect_to_encrypt` returning CTX_ACT_REDIRECT
	 * with also the encryption mark set.
	 */
	TEST("overlay-mark-set", {
		set_identity_mark(ctx, SOURCE_IDENTITY, MARK_MAGIC_OVERLAY);
		ret = ipsec_maybe_redirect_to_encrypt(ctx, proto, SOURCE_IDENTITY);
		assert(ctx->mark == ipsec_encode_encryption_mark(TARGET_SPI, DST_NODE_ID));
		assert(ret == CTX_ACT_REDIRECT);
	})

	test_finish();
}

PKTGEN("tc", "ipsec_redirect_tunnel4_v4")
int ipsec_redirect_tunnel4_v4_pktgen(struct __ctx_buff *ctx)
{
	return generate_vxlan_packet(ctx, true, true);
}

CHECK("tc", "ipsec_redirect_tunnel4_v4")
int ipsec_redirect_tunnel4_v4_check(__maybe_unused struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx, true);
}

PKTGEN("tc", "ipsec_redirect_tunnel4_v6")
int ipsec_redirect_tunnel4_v6_pktgen(struct __ctx_buff *ctx)
{
	return generate_vxlan_packet(ctx, true, false);
}

CHECK("tc", "ipsec_redirect_tunnel4_v6")
int ipsec_redirect_tunnel4_v6_check(__maybe_unused struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx, true);
}

PKTGEN("tc", "ipsec_redirect_tunnel6_v4")
int ipsec_redirect_tunnel6_v4_pktgen(struct __ctx_buff *ctx)
{
	return generate_vxlan_packet(ctx, false, true);
}

CHECK("tc", "ipsec_redirect_tunnel6_v4")
int ipsec_redirect_tunnel6_v4_check(__maybe_unused struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx, false);
}

PKTGEN("tc", "ipsec_redirect_tunnel6_v6")
int ipsec_redirect_tunnel6_v6_pktgen(struct __ctx_buff *ctx)
{
	return generate_vxlan_packet(ctx, false, true);
}

CHECK("tc", "ipsec_redirect_tunnel6_v6")
int ipsec_redirect_tunnel6_v6_check(__maybe_unused struct __ctx_buff *ctx)
{
	return ipsec_redirect_checks(ctx, false);
}
