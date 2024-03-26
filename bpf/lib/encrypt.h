/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ENCRYPT_H_
#define __LIB_ENCRYPT_H_

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "lib/common.h"
#include "lib/drop.h"
#include "lib/eps.h"

static __always_inline __u8 get_min_encrypt_key(__u8 peer_key __maybe_unused)
{
#ifdef ENABLE_IPSEC
	__u8 local_key = 0;
	__u32 encrypt_key = 0;
	struct encrypt_config *cfg;

	cfg = map_lookup_elem(&ENCRYPT_MAP, &encrypt_key);
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
	__u16 *node_id;

	node_ip.family = ENDPOINT_KEY_IPV4;
	node_ip.ip4 = ip4;
	node_id = map_lookup_elem(&NODE_MAP, &node_ip);
	if (!node_id)
		return 0;
	return *node_id;
}
# endif /* ENABLE_IPV4 */

# ifdef ENABLE_IPV6
static __always_inline __u16
lookup_ip6_node_id(const union v6addr *ip6)
{
	struct node_key node_ip = {};
	__u16 *node_id;

	node_ip.family = ENDPOINT_KEY_IPV6;
	node_ip.ip6 = *ip6;
	node_id = map_lookup_elem(&NODE_MAP, &node_ip);
	if (!node_id)
		return 0;
	return *node_id;
}
# endif /* ENABLE_IPV6 */

static __always_inline void
set_ipsec_decrypt_mark(struct __ctx_buff *ctx, __u16 node_id)
{
	/* Decrypt "key" is determined by SPI and originating node */
	ctx->mark = MARK_MAGIC_DECRYPT | node_id << 16;
}

static __always_inline int
set_ipsec_encrypt(struct __ctx_buff *ctx, __u8 key, __u32 tunnel_endpoint,
		  __u32 seclabel, bool use_meta)
{
	/* IPSec is performed by the stack on any packets with the
	 * MARK_MAGIC_ENCRYPT bit set. During the process though we
	 * lose the lxc context (seclabel and tunnel endpoint). The
	 * tunnel endpoint can be looked up from daddr but the sec
	 * label is stashed in the mark or cb, and extracted in
	 * bpf_host to send ctx onto tunnel for encap.
	 */

	struct node_key node_ip = {};
	__u16 *node_id;

	node_ip.family = ENDPOINT_KEY_IPV4;
	node_ip.ip4 = tunnel_endpoint;
	node_id = map_lookup_elem(&NODE_MAP, &node_ip);
	if (!node_id)
		return DROP_NO_NODE_ID;

	set_identity_meta(ctx, seclabel);
	if (use_meta)
		set_encrypt_key_meta(ctx, key, *node_id);
	else
		set_encrypt_key_mark(ctx, key, *node_id);
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
			return send_drop_notify_error(ctx, 0, DROP_NO_NODE_ID,
						      CTX_ACT_DROP,
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
	return ctx_redirect(ctx, CILIUM_IFINDEX, 0);
#endif /* ENABLE_ROUTING */
}
#else
static __always_inline int
do_decrypt(struct __ctx_buff __maybe_unused *ctx, __u16 __maybe_unused proto)
{
	return CTX_ACT_OK;
}
#endif /* ENABLE_IPSEC */
#endif /* __LIB_ENCRYPT_H_ */

