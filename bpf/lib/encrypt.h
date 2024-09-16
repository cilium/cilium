/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "lib/common.h"
#include "lib/drop.h"
#include "lib/eps.h"
#include "lib/ipv4.h"
#include "lib/vxlan.h"
#include "lib/node.h"
#include "lib/identity.h"

/* We cap key index at 4 bits because mark value is used to map ctx to key */
#define MAX_KEY_INDEX 15

#ifdef ENABLE_IPSEC
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct encrypt_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} cilium_encrypt_state __section_maps_btf;
#endif

static __always_inline __u8 get_min_encrypt_key(__u8 peer_key __maybe_unused)
{
#ifdef ENABLE_IPSEC
	__u8 local_key = 0;
	__u32 encrypt_key = 0;
	struct encrypt_config *cfg;

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
# ifdef ENABLE_IPV4
static __always_inline __u16
lookup_ip4_node_id(__u32 ip4)
{
	struct node_key node_ip = {};
	struct node_value *node_value = NULL;

	node_ip.family = ENDPOINT_KEY_IPV4;
	node_ip.ip4 = ip4;
	node_value = map_lookup_elem(&cilium_node_map_v2, &node_ip);
	if (!node_value)
		return 0;
	if (!node_value->id)
		return 0;
	return node_value->id;
}
# endif /* ENABLE_IPV4 */

# ifdef ENABLE_IPV6
static __always_inline __u16
lookup_ip6_node_id(const union v6addr *ip6)
{
	struct node_key node_ip = {};
	struct node_value *node_value = NULL;

	node_ip.family = ENDPOINT_KEY_IPV6;
	node_ip.ip6 = *ip6;
	node_value = map_lookup_elem(&cilium_node_map_v2, &node_ip);
	if (!node_value)
		return 0;
	if (!node_value->id)
		return 0;
	return node_value->id;
}
# endif /* ENABLE_IPV6 */

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

static __always_inline void
set_ipsec_decrypt_mark(struct __ctx_buff *ctx, __u16 node_id)
{
	/* Decrypt "key" is determined by SPI and originating node */
	ctx->mark = MARK_MAGIC_DECRYPT | node_id << 16;
}

static __always_inline int
set_ipsec_encrypt(struct __ctx_buff *ctx, __u8 spi, __u32 tunnel_endpoint,
		  __u32 seclabel, bool use_meta, bool use_spi_from_map)
{
	/* IPSec is performed by the stack on any packets with the
	 * MARK_MAGIC_ENCRYPT bit set. During the process though we
	 * lose the lxc context (seclabel and tunnel endpoint). The
	 * tunnel endpoint can be looked up from daddr but the sec
	 * label is stashed in the mark or cb, and extracted in
	 * bpf_host to send ctx onto tunnel for encap.
	 */

	struct node_key node_ip = {};
	struct node_value *node_value = NULL;
	__u32 mark;

	node_ip.family = ENDPOINT_KEY_IPV4;
	node_ip.ip4 = tunnel_endpoint;
	node_value = map_lookup_elem(&cilium_node_map_v2, &node_ip);
	if (!node_value || !node_value->id)
		return DROP_NO_NODE_ID;

	if (use_spi_from_map)
		spi = get_min_encrypt_key(node_value->spi);

	mark = ipsec_encode_encryption_mark(spi, node_value->id);

	set_identity_meta(ctx, seclabel);
	if (use_meta)
		ctx->cb[CB_ENCRYPT_MAGIC] = mark;
	ctx->mark = mark;

	return CTX_ACT_OK;
}

static __always_inline int
do_decrypt(struct __ctx_buff *ctx, __u16 proto)
{
	void *data, *data_end;
	__u8 protocol = 0;
	__u16 node_id = 0;
	bool decrypted;
#ifdef ENABLE_IPV6
	struct ipv6hdr *ip6;
#endif
#ifdef ENABLE_IPV4
	struct iphdr *ip4;
#endif

	decrypted = ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);

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
			return send_drop_notify_error(ctx, UNKNOWN_ID, DROP_NO_NODE_ID,
						      METRIC_INGRESS);
		set_ipsec_decrypt_mark(ctx, node_id);

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
	return ctx_redirect(ctx, CILIUM_HOST_IFINDEX, 0);
#endif /* ENABLE_ENDPOINT_ROUTES */
}

/* checks whether a IPsec redirect should be performed for the security id
 * we do not IPsec encrypt:
 * 1. Host-to-Host or Pod-to-Host traffic
 * 2. Traffic leaving the cluster
 * 3. Remote nodes including Kube API server
 * 4. Traffic is already ESP encrypted
 */
static __always_inline int
ipsec_redirect_sec_id_ok(__u32 src_sec_id, __u32 dst_sec_id, int ip_proto) {
	if (ip_proto == IPPROTO_ESP)
		return 0;
	if (src_sec_id == HOST_ID)
		return 0;
	if (dst_sec_id == HOST_ID)
		return 0;
	if (!identity_is_cluster(dst_sec_id))
		return 0;
	if (!identity_is_cluster(src_sec_id))
		return 0;
	if (identity_is_remote_node(dst_sec_id))
		return 0;
	if (identity_is_remote_node(src_sec_id))
		return 0;
	return 1;
}

static __always_inline int
ipsec_maybe_redirect_to_encrypt(struct __ctx_buff *ctx, __be16 proto,
				__u32 src_sec_identity)
{
	struct remote_endpoint_info __maybe_unused *dst = NULL;
	struct remote_endpoint_info __maybe_unused *src = NULL;
	void *data __maybe_unused, *data_end __maybe_unused;
	struct iphdr __maybe_unused *ip4;
	struct ipv6hdr __maybe_unused *ip6;
	__u32 magic __maybe_unused = 0;
	int ip_proto = 0;
	int ret = 0;
	union macaddr dst_mac = CILIUM_NET_MAC;

	if (!eth_is_supported_ethertype(proto))
		return DROP_UNSUPPORTED_L2;

	/* if we are in tunnel mode the overlay prog can detect if the packet
	 * was already encrypted before encapsulation.
	 *
	 * if it was, we can simply short-circuit here and return, no encryption
	 * is required
	 *
	 * this would only be the case when transitioning from v1.17 -> v1.18
	 * and can be removed on v1.19 release.
	 */
# if defined(TUNNEL_MODE)
	if (ctx_is_overlay_encrypted(ctx))
		return CTX_ACT_OK;
# endif /* TUNNEL_MODE */

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
			/* NOTE: we confirm double-encryption will not occur
			 * above in the `ctx_is_overlay_encrypted` check
			 */

			/* see comment in the native-routing mode call. */
			ret = set_ipsec_encrypt(ctx, 0, ip4->daddr,
						get_identity(ctx), true,
						true);
			if (ret != CTX_ACT_OK)
				return ret;
			goto overlay_encrypt;
		}
#  endif /* TUNNEL_MODE */

		ip_proto = ip4->protocol;

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
#ifndef TUNNEL_MODE
		/* handle native routing ipv6 */
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		ip_proto = ip6->nexthdr;

		dst = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);

		if (src_sec_identity == UNKNOWN_ID) {
			src = lookup_ip6_remote_endpoint((union v6addr *)&ip6->saddr, 0);
			if (!src)
				return CTX_ACT_OK;

			src_sec_identity = src->sec_identity;
		}
		break;
#endif /* TUNNEL_MODE */
# endif /* ENABLE_IPv6 */
	default:
		return CTX_ACT_OK;
	}

	if (!dst)
		return CTX_ACT_OK;

	if (!dst->tunnel_endpoint.ip4)
		return CTX_ACT_OK;

	if (!ipsec_redirect_sec_id_ok(src_sec_identity, dst->sec_identity,
				      ip_proto))
		return CTX_ACT_OK;

	/* mark packet for encryption
	 * for now, we flip the 'use_meta' flag true, this is required since
	 * rhel 8.6 kernels lack a patch which preserves marks through eBPF
	 * redirects on the same host-ns.
	 *
	 * when either 1. RHEL backports this patch or 2. Cilium no longer
	 * supports rhel 8.6 'use_meta' can be flipped back to false and we
	 * can rely only on the mark.
	 */
	ret = set_ipsec_encrypt(ctx, 0, dst->tunnel_endpoint.ip4,
				src_sec_identity, true, true);
	if (ret != CTX_ACT_OK)
		return ret;

#  if defined(TUNNEL_MODE) && defined(ENABLE_IPV4)
overlay_encrypt:
#  endif
	/* redirect to the ingress side of CILIUM_NET.
	 * this will subject the packet to the ingress XFRM hooks,
	 * encrypting the packet.
	 *
	 * the encrypted packet will be recirculated to the stack and the final
	 * egress will occur toward the IPsec tunnel's destination.
	 */
	if (eth_store_daddr(ctx, (const __u8 *)&dst_mac, 0) != 0)
		return DROP_WRITE_ERROR;

	ret = ctx_redirect(ctx, CILIUM_NET_IFINDEX, BPF_F_INGRESS);
	if (ret != CTX_ACT_REDIRECT)
		return DROP_INVALID;
	return ret;
}

#if defined(ENABLE_ENCRYPTED_OVERLAY)
/* Sets the encryption mark on an overlay (VXLAN) packet and redirects the
 * packet to the ingress side of it's associated ifindex.
 *
 * The recirculated overlay packet will then be subjected to XFRM hooks in the
 * output routing path, since the original src/dst of the overlay packet routes
 * off-host.
 *
 * This function is useful when you want to encrypt overlay traffic and use the
 * underlay to deliver encrypted overlay traffic to the remote node.
 * For this to work the IPSec control plane must install XFRM policies and
 * states which set the tunnel source and destination to the underlay address of
 * the destination node.
 *
 * If the redirect to the ingress side of ctx->ingress is successful
 * CTX_ACT_REDIRECT is returned, otherwise an error code is returned.
 *
 * Be aware that the redirected-to interface needs to have the following
 * sysctl enabled for this to work correctly (per-device is fine)
 *   - net.ipv4.conf.default.rp_filter = 0
 *   - net.ipv4.conf.default.accept_local = 1
 */
static __always_inline int
encrypt_overlay_and_redirect(struct __ctx_buff *ctx)
{
	struct iphdr *ip4, *inner_ipv4 = NULL;
	struct endpoint_info *ep_info = NULL;
	void *data, *data_end;
	__u8 dst_mac = 0;
	__u32 l4_off;
	int ret = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	ret = vxlan_get_inner_ipv4(data, data_end, l4_off, &inner_ipv4);
	if (!ret)
		return DROP_INVALID;

	ep_info = __lookup_ip4_endpoint(inner_ipv4->saddr);
	if (!ep_info)
		return DROP_INVALID;

	/*
	 * this is a vxlan packet so ip4->daddr is the tunnel endpoint
	 */
	ret = set_ipsec_encrypt(ctx, 0, ip4->daddr, ep_info->sec_id, false,
				true);
	if (ret != CTX_ACT_OK)
		return ret;

	/*
	 * source mac is our current egress interface, lets copy it to dmac
	 * so redirecting to ingress side of the same interface doesn't fail.
	 */
	if (eth_load_saddr(ctx, &dst_mac, 0) != 0)
		return DROP_INVALID;
	if (eth_store_daddr(ctx, &dst_mac, 0) != 0)
		return DROP_WRITE_ERROR;

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	/* right now, the VNI of this packet is ENCRYPTED_OVERLAY_ID, we need
	 * to rewrite this VNI to the source's sec id before we transmit it
	 */
	if (!vxlan_rewrite_vni(ctx, data, data_end, l4_off, ep_info->sec_id))
		return DROP_INVALID;

	/* redirect to ingress side of ifindex so the packet has xfrm applied */
	ret = ctx_redirect(ctx, ctx->ifindex, BPF_F_INGRESS);
	if (ret != CTX_ACT_REDIRECT)
		return DROP_INVALID;

	return ret;
}
#endif /* ENABLE_ENCRYPTED_OVERLAY */

#else
static __always_inline int
do_decrypt(struct __ctx_buff __maybe_unused *ctx, __u16 __maybe_unused proto)
{
	return CTX_ACT_OK;
}
#endif /* ENABLE_IPSEC */
