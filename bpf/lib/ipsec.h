/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "lib/common.h"
#include "lib/encrypt.h"
#include "lib/eps.h"
#include "lib/ipv4.h"
#include "lib/node.h"
#include "lib/identity.h"

/* We cap key index at 4 bits because mark value is used to map ctx to key */
#define MAX_KEY_INDEX 15

/* encrypt_config is the current encryption context on the node */
struct encrypt_config {
	__u8 encrypt_key;
} __packed;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct encrypt_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG_COND);
} cilium_encrypt_state __section_maps_btf;

static __always_inline __u8 get_min_encrypt_key(__u8 peer_key __maybe_unused)
{
#ifdef ENABLE_IPSEC
	__u8 local_key = 0;
	__u32 encrypt_key = 0;
	const struct encrypt_config *cfg;

	cfg = map_lookup_elem(&cilium_encrypt_state, &encrypt_key);
	/* Having no key info for a context is the same as no encryption */
	if (cfg)
		local_key = cfg->encrypt_key;

	/* If both ends can encrypt/decrypt use smaller of the two this
	 * way both ends will have keys installed assuming key IDs are
	 * always increasing. However, we have to handle roll-over case
	 * and to do this safely we assume keys are no more than one ahead.
	 * We expect user/control-place to accomplish this. Notice zero
	 * will always be returned if either local or peer have the zero
	 * key indicating no encryption.
	 */
	if (peer_key == MAX_KEY_INDEX)
		return local_key == 1 ? peer_key : local_key;
	if (local_key == MAX_KEY_INDEX)
		return peer_key == 1 ? local_key : peer_key;
	return local_key < peer_key ? local_key : peer_key;
#else
	return 0;
#endif /* ENABLE_IPSEC */
}

#ifdef ENABLE_IPSEC
/**
 * or_encrypt_key - mask and shift key into encryption format
 */
static __always_inline __u32 or_encrypt_key(__u8 key)
{
	return (((__u32)key & 0x0F) << 12) | MARK_MAGIC_ENCRYPT;
}

static __always_inline __u32
ipsec_encode_encryption_mark(__u8 key, __u32 node_id)
{
	return or_encrypt_key(key) | node_id << 16;
}

static __always_inline int
set_ipsec_encrypt(struct __ctx_buff *ctx,
		  const struct remote_endpoint_info *info,
		  __u32 seclabel, bool use_meta)
{
	/* IPSec is performed by the stack on any packets with the
	 * MARK_MAGIC_ENCRYPT bit set.
	 *
	 * The source's security identity in CB_ENCRYPT_IDENTITY is
	 * preserved across the XFRM traversal.
	 */

	const struct node_value *node_value = NULL;
	__u32 mark;
	__u8 spi;

	node_value = lookup_node(info);
	if (!node_value || !node_value->id)
		return DROP_NO_NODE_ID;

	spi = get_min_encrypt_key(node_value->spi);

	mark = ipsec_encode_encryption_mark(spi, node_value->id);

	set_encrypt_identity_meta(ctx, seclabel);
	if (use_meta)
		ctx->cb[CB_ENCRYPT_MAGIC] = mark;
	ctx->mark = mark;

	return CTX_ACT_OK;
}

static __always_inline int
do_decrypt(struct __ctx_buff *ctx, __be16 proto)
{
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	void *data, *data_end;
	__u8 protocol = 0;
	__u16 node_id = 0;
	bool decrypted = ctx_is_decrypt(ctx);

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6)) {
			ctx->mark = 0;
			return CTX_ACT_OK;
		}
		protocol = ip6->nexthdr;
		if (!decrypted)
			node_id = lookup_ip6_node_id((union v6addr *)&ip6->saddr);
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
			ctx->mark = 0;
			return CTX_ACT_OK;
		}
		protocol = ip4->protocol;
		if (!decrypted)
			node_id = lookup_ip4_node_id(ip4->saddr);
		break;
#endif
	default:
		return CTX_ACT_OK;
	}

	if (!decrypted) {
		/* Allow all non-ESP packets up the stack per normal case
		 * without encryption enabled.
		 */
		if (protocol != IPPROTO_ESP)
			return CTX_ACT_OK;

		if (!node_id)
			return DROP_NO_NODE_ID;

		set_decrypt_mark(ctx, node_id);

		/* We are going to pass this up the stack for IPsec decryption
		 * but eth_type_trans may already have labeled this as an
		 * OTHERHOST type packet. To avoid being dropped by IP stack
		 * before IPSec can be processed mark as a HOST packet.
		 */
		ctx_change_type(ctx, PACKET_HOST);
		return CTX_ACT_OK;
	}
	ctx->mark = 0;
#ifdef ENABLE_ENDPOINT_ROUTES
	return CTX_ACT_OK;
#else
	return ctx_redirect(ctx, CONFIG(cilium_host_ifindex), 0);
#endif /* ENABLE_ENDPOINT_ROUTES */
}

/* checks whether a IPsec redirect should be performed for the source
 */
static __always_inline int
ipsec_redirect_sec_id_ok(__u32 src_sec_id) {
	if (src_sec_id == HOST_ID)
		return 0;
	if (!identity_is_cluster(src_sec_id))
		return 0;
	if (identity_is_remote_node(src_sec_id))
		return 0;
	return 1;
}

static __always_inline int
ipsec_maybe_redirect_to_encrypt(struct __ctx_buff *ctx, __be16 proto,
				__u32 src_sec_identity)
{
	struct remote_endpoint_info __maybe_unused fake_info = {0};
	const struct remote_endpoint_info __maybe_unused *dst = NULL;
	const struct remote_endpoint_info __maybe_unused *src = NULL;
	void *data __maybe_unused, *data_end __maybe_unused;
	struct iphdr __maybe_unused *ip4;
	struct ipv6hdr __maybe_unused *ip6;
	int ret = 0;
	union macaddr dst_mac = CILIUM_NET_MAC;

	if (!eth_is_supported_ethertype(proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

#  if defined(TUNNEL_MODE)
		/* tunnel mode needs a bit of special handling when
		 * encapsulated packets get here the destination address is
		 * already a cluster node IP.
		 *
		 * the security ID is appended to the mark in the overlay prog
		 * and we can extract this with 'get_identity'.
		 * additionally, this is a VXLAN packet so ip4->daddr is the ip
		 * of the destination host already and can be passed into
		 * set_ipsec_encrypt to obtain the correct node ID and spi.
		 */
		if (ctx_is_overlay(ctx)) {
			fake_info.tunnel_endpoint.ip4 = ip4->daddr;
			fake_info.flag_has_tunnel_ep = true;

			dst = &fake_info;
			src_sec_identity = get_identity(ctx);
			goto overlay_encrypt;
		}
#  endif /* TUNNEL_MODE */

		dst = lookup_ip4_remote_endpoint(ip4->daddr, 0);

		if (src_sec_identity == UNKNOWN_ID) {
			src = lookup_ip4_remote_endpoint(ip4->saddr, 0);
			if (!src)
				return CTX_ACT_OK;

			src_sec_identity = src->sec_identity;
		}
		break;
# endif /* ENABLE_IPV4 */

# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		/* handle native routing ipv6 */
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

#  if defined(TUNNEL_MODE)
		/* See comment in IPv4 case.
		 */
		if (ctx_is_overlay(ctx)) {
			ipv6_addr_copy_unaligned(&fake_info.tunnel_endpoint.ip6,
						 (union v6addr *)&ip6->daddr);
			fake_info.flag_has_tunnel_ep = true;
			fake_info.flag_ipv6_tunnel_ep = true;

			dst = &fake_info;
			src_sec_identity = get_identity(ctx);
			goto overlay_encrypt;
		}
#  endif /* TUNNEL_MODE */

		dst = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);

		if (src_sec_identity == UNKNOWN_ID) {
			src = lookup_ip6_remote_endpoint((union v6addr *)&ip6->saddr, 0);
			if (!src)
				return CTX_ACT_OK;

			src_sec_identity = src->sec_identity;
		}
		break;
# endif /* ENABLE_IPv6 */
	default:
		return CTX_ACT_OK;
	}

	if (!dst || !dst->flag_has_tunnel_ep || !dst->key)
		return CTX_ACT_OK;

	if (!ipsec_redirect_sec_id_ok(src_sec_identity))
		return CTX_ACT_OK;

#  if defined(TUNNEL_MODE)
overlay_encrypt:
#  endif
	/* mark packet for encryption
	 * for now, we flip the 'use_meta' flag true, this is required since
	 * rhel 8.6 kernels lack a patch which preserves marks through eBPF
	 * redirects on the same host-ns.
	 *
	 * when either 1. RHEL backports this patch or 2. Cilium no longer
	 * supports rhel 8.6 'use_meta' can be flipped back to false and we
	 * can rely only on the mark.
	 */
	ret = set_ipsec_encrypt(ctx, dst, src_sec_identity, true);
	if (ret != CTX_ACT_OK)
		return ret;

	/* redirect to the ingress side of CILIUM_NET.
	 * this will subject the packet to the ingress XFRM hooks,
	 * encrypting the packet.
	 *
	 * the encrypted packet will be recirculated to the stack and the final
	 * egress will occur toward the IPsec tunnel's destination.
	 */
	if (eth_store_daddr(ctx, (const __u8 *)&dst_mac, 0) != 0)
		return DROP_WRITE_ERROR;

	ret = ctx_redirect(ctx, CONFIG(cilium_net_ifindex), BPF_F_INGRESS);
	if (ret != CTX_ACT_REDIRECT)
		return DROP_INVALID;
	return ret;
}
#else
static __always_inline int
do_decrypt(struct __ctx_buff __maybe_unused *ctx, __be16 __maybe_unused proto)
{
	return CTX_ACT_OK;
}
#endif /* ENABLE_IPSEC */
