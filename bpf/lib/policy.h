/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_POLICY_H_
#define __LIB_POLICY_H_

#include <linux/icmp.h>

#include "drop.h"
#include "dbg.h"
#include "eps.h"
#include "maps.h"

#ifdef SOCKMAP
static __always_inline int
policy_sk_egress(__u32 identity, __u32 ip,  __u16 dport)
{
	void *map = lookup_ip4_endpoint_policy_map(ip);
	int dir = CT_EGRESS;
	__u8 proto = IPPROTO_TCP;
	struct policy_entry *policy;
	struct policy_key key = {
		.sec_label = identity,
		.dport = dport,
		.protocol = proto,
		.egress = !dir,
		.pad = 0,
	};

	if (!map)
		return CTX_ACT_OK;

	/* Start with L3/L4 lookup. */
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Need byte counter */
		__sync_fetch_and_add(&policy->packets, 1);
		if (unlikely(policy->deny))
			return DROP_POLICY_DENY;
		return policy->proxy_port;
	}

	/* L4-only lookup. */
	key.sec_label = 0;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Need byte counter */
		__sync_fetch_and_add(&policy->packets, 1);
		if (unlikely(policy->deny))
			return DROP_POLICY_DENY;
		return policy->proxy_port;
	}
	key.sec_label = identity;

	/* If L4 policy check misses, fall back to L3. */
	key.dport = 0;
	key.protocol = 0;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Need byte counter */
		__sync_fetch_and_add(&policy->packets, 1);
		if (unlikely(policy->deny))
			return DROP_POLICY_DENY;
		return CTX_ACT_OK;
	}

	/* Final fallback if allow-all policy is in place. */
	key.sec_label = 0;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		/* FIXME: Need byte counter */
		__sync_fetch_and_add(&policy->packets, 1);
		if (unlikely(policy->deny))
			return DROP_POLICY_DENY;
		return CTX_ACT_OK;
	}

	return DROP_POLICY;
}
#else
static __always_inline void
account(struct __ctx_buff *ctx, struct policy_entry *policy)
{
	/* FIXME: Use per cpu counters */
	__sync_fetch_and_add(&policy->packets, 1);
	__sync_fetch_and_add(&policy->bytes, ctx_full_len(ctx));
}

static __always_inline int
__policy_can_access(const void *map, struct __ctx_buff *ctx, __u32 localID,
		    __u32 remoteID, __u16 dport, __u8 proto, int dir,
		    bool is_untracked_fragment, __u8 *match_type)
{
	struct policy_entry *policy;
	struct policy_key key = {
		.sec_label = remoteID,
		.dport = dport,
		.protocol = proto,
		.egress = !dir,
		.pad = 0,
	};

#ifdef ALLOW_ICMP_FRAG_NEEDED
	/* When ALLOW_ICMP_FRAG_NEEDED is defined we allow all packets
	 * of ICMP type 3 code 4 - Fragmentation Needed.
	 */
	if (proto == IPPROTO_ICMP) {
		void *data, *data_end;
		struct icmphdr icmphdr __align_stack_8;
		struct iphdr *ip4;
		__u32 off;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
		if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;

		if (icmphdr.type == ICMP_DEST_UNREACH &&
		    icmphdr.code == ICMP_FRAG_NEEDED)
			return CTX_ACT_OK;
	}
#endif /* ALLOW_ICMP_FRAG_NEEDED */

	/* L4 lookup can't be done on untracked fragments. */
	if (!is_untracked_fragment) {
		/* Start with L3/L4 lookup. */
		policy = map_lookup_elem(map, &key);
		if (likely(policy)) {
			cilium_dbg3(ctx, DBG_L4_CREATE, remoteID, localID,
				    dport << 16 | proto);

			account(ctx, policy);
			*match_type = POLICY_MATCH_L3_L4;
			if (unlikely(policy->deny))
				return DROP_POLICY_DENY;
			return policy->proxy_port;
		}

		/* L4-only lookup. */
		key.sec_label = 0;
		policy = map_lookup_elem(map, &key);
		if (likely(policy)) {
			account(ctx, policy);
			*match_type = POLICY_MATCH_L4_ONLY;
			if (unlikely(policy->deny))
				return DROP_POLICY_DENY;
			return policy->proxy_port;
		}
		key.sec_label = remoteID;
	}

	/* If L4 policy check misses, fall back to L3. */
	key.dport = 0;
	key.protocol = 0;
	policy = map_lookup_elem(map, &key);
	if (likely(policy)) {
		account(ctx, policy);
		*match_type = POLICY_MATCH_L3_ONLY;
		if (unlikely(policy->deny))
			return DROP_POLICY_DENY;
		return CTX_ACT_OK;
	}

	/* Final fallback if allow-all policy is in place. */
	key.sec_label = 0;
	policy = map_lookup_elem(map, &key);
	if (policy) {
		account(ctx, policy);
		*match_type = POLICY_MATCH_ALL;
		if (unlikely(policy->deny))
			return DROP_POLICY_DENY;
		return CTX_ACT_OK;
	}

	if (ctx_load_meta(ctx, CB_POLICY))
		return CTX_ACT_OK;

	if (is_untracked_fragment)
		return DROP_FRAG_NOSUPPORT;

	return DROP_POLICY;
}

/**
 * Determine whether the policy allows this traffic on ingress.
 * @arg ctx		Packet to allow or deny
 * @arg srcID		Source security identity for this packet
 * @arg dstID		Destination security identity for this packet
 * @arg dport		Destination port of this packet
 * @arg proto		L3 Protocol of this packet
 * @arg is_untracked_fragment	True if packet is a TCP/UDP datagram fragment
 *				AND IPv4 fragment tracking is disabled
 * @arg match_type		Pointer to store layers used for policy match
 *
 * Returns:
 *   - Positive integer indicating the proxy_port to handle this traffic
 *   - CTX_ACT_OK if the policy allows this traffic based only on labels/L3/L4
 *   - Negative error code if the packet should be dropped
 */
static __always_inline int
policy_can_access_ingress(struct __ctx_buff *ctx, __u32 srcID, __u32 dstID,
			  __u16 dport, __u8 proto, bool is_untracked_fragment,
			  __u8 *match_type, __u8 *audited)
{
	int ret;

	ret = __policy_can_access(&POLICY_MAP, ctx, dstID, srcID, dport,
				  proto, CT_INGRESS, is_untracked_fragment,
				  match_type);
	if (ret >= CTX_ACT_OK)
		return ret;

	cilium_dbg(ctx, DBG_POLICY_DENIED, srcID, dstID);

	*audited = 0;
#ifdef POLICY_AUDIT_MODE
	if (IS_ERR(ret)) {
		ret = CTX_ACT_OK;
		*audited = 1;
	}
#endif

	return ret;
}

#ifdef ENCAP_IFINDEX
static __always_inline bool is_encap(__u16 dport, __u8 proto)
{
	return proto == IPPROTO_UDP &&
		(dport == bpf_htons(PORT_UDP_VXLAN) ||
		 dport == bpf_htons(PORT_UDP_GENEVE) ||
		 dport == bpf_htons(PORT_UDP_VXLAN_LINUX));
}
#endif

static __always_inline int
policy_can_egress(struct __ctx_buff *ctx, __u32 srcID, __u32 dstID,
		  __u16 dport, __u8 proto, __u8 *match_type, __u8 *audited)
{
	int ret;

#ifdef ENCAP_IFINDEX
	if (srcID != HOST_ID && is_encap(dport, proto))
		return DROP_ENCAP_PROHIBITED;
#endif
	ret = __policy_can_access(&POLICY_MAP, ctx, srcID, dstID, dport, proto,
				  CT_EGRESS, false, match_type);
	if (ret >= 0)
		return ret;
	cilium_dbg(ctx, DBG_POLICY_DENIED, srcID, dstID);
	*audited = 0;
#ifdef POLICY_AUDIT_MODE
	if (IS_ERR(ret)) {
		ret = CTX_ACT_OK;
		*audited = 1;
	}
#endif
	return ret;
}

static __always_inline int policy_can_egress6(struct __ctx_buff *ctx,
					      const struct ipv6_ct_tuple *tuple,
					      __u32 srcID, __u32 dstID,
					      __u8 *match_type, __u8 *audited)
{
	return policy_can_egress(ctx, srcID, dstID, tuple->dport,
				 tuple->nexthdr, match_type, audited);
}

static __always_inline int policy_can_egress4(struct __ctx_buff *ctx,
					      const struct ipv4_ct_tuple *tuple,
					      __u32 srcID, __u32 dstID,
					      __u8 *match_type, __u8 *audited)
{
	return policy_can_egress(ctx, srcID, dstID, tuple->dport,
				 tuple->nexthdr, match_type, audited);
}

/**
 * Mark ctx to skip policy enforcement
 * @arg ctx	packet
 *
 * Will cause the packet to ignore the policy enforcement layer and
 * be considered accepted despite of the policy outcome.
 */
static __always_inline void policy_mark_skip(struct __ctx_buff *ctx)
{
	ctx_store_meta(ctx, CB_POLICY, 1);
}

static __always_inline void policy_clear_mark(struct __ctx_buff *ctx)
{
	ctx_store_meta(ctx, CB_POLICY, 0);
}
#endif /* SOCKMAP */
#endif
