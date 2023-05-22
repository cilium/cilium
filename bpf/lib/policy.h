/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_POLICY_H_
#define __LIB_POLICY_H_

#include <linux/icmp.h>

#include "drop.h"
#include "dbg.h"
#include "eps.h"
#include "maps.h"

static __always_inline int
__account_and_check(struct __ctx_buff *ctx, struct policy_entry *policy,
		    __s8 *ext_err, __u16 *proxy_port)
{
	/* FIXME: Use per cpu counters */
	__sync_fetch_and_add(&policy->packets, 1);
	__sync_fetch_and_add(&policy->bytes, ctx_full_len(ctx));

	if (unlikely(policy->deny))
		return DROP_POLICY_DENY;

	*proxy_port = policy->proxy_port;
	if (unlikely(policy->auth_type)) {
		if (ext_err)
			*ext_err = (__s8)policy->auth_type;
		return DROP_POLICY_AUTH_REQUIRED;
	}
	return CTX_ACT_OK;
}

static __always_inline int
__policy_can_access(const void *map, struct __ctx_buff *ctx, __u32 local_id,
		    __u32 remote_id, __u16 dport, __u8 proto, int dir,
		    bool is_untracked_fragment, __u8 *match_type, __s8 *ext_err,
		    __u16 *proxy_port)
{
	struct policy_entry *policy;
	struct policy_entry *l4policy;
	struct policy_key key = {
		.lpm_key = { POLICY_FULL_PREFIX, {} }, /* always look up with unwildcarded data */
		.sec_label = remote_id,
		.egress = !dir,
		.pad = 0,
		.protocol = proto,
		.dport = dport,
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
		    icmphdr.code == ICMP_FRAG_NEEDED) {
			*proxy_port = 0;
			return CTX_ACT_OK;
		}
	}
#endif /* ALLOW_ICMP_FRAG_NEEDED */

#ifdef ENABLE_ICMP_RULE
	if (proto == IPPROTO_ICMP) {
		void *data, *data_end;
		struct iphdr *ip4;
		struct icmphdr icmphdr __align_stack_8;
		__u32 off;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
		if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;

		/* Convert from unsigned char to unsigned short considering byte order(little-endian).
		 * In the little-endian case, for example, 2byte data "AB" convert to "BA".
		 * Therefore, the "icmp_type" should be shifted not just casting.
		 */
		key.dport = (__u16)(icmphdr.type << 8);
	} else if (proto == IPPROTO_ICMPV6) {
		void *data, *data_end;
		struct ipv6hdr *ip6;
		__u32 off;
		__u8 icmp_type;
		__u8 nexthdr;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		nexthdr = ip6->nexthdr;
		off = ((void *)ip6 - data) + ipv6_hdrlen(ctx, &nexthdr);
		if (ctx_load_bytes(ctx, off, &icmp_type, sizeof(icmp_type)) < 0)
			return DROP_INVALID;

		/* Convert from unsigned char to unsigned short considering byte order(little-endian).
		 * In the little-endian case, for example, 2byte data "AB" convert to "BA".
		 * Therefore, the "icmp_type" should be shifted not just casting.
		 */
		key.dport = (__u16)(icmp_type << 8);
	}
#endif /* ENABLE_ICMP_RULE */

	/* Policy match precedence:
	 * 1. id/proto/port  (L3/L4)
	 * 2. ANY/proto/port (L4-only)
	 * 3. id/proto/ANY   (L3-proto)
	 * 4. ANY/proto/ANY  (Proto-only)
	 * 5. id/ANY/ANY     (L3-only)
	 * 6. ANY/ANY/ANY    (All)
	 */

	/* Start with L3/L4 lookup.
	 * LPM precedence order with L3:
	 * 1. id/proto/port
	 * 3. id/proto/ANY (check L4-only match first)
	 * 5. id/ANY/ANY   (check proto match first)
	 *
	 * Note: Untracked fragments always have zero ports in the tuple so they can
	 * only match entries that have fully wildcarded ports.
	 */
	policy = map_lookup_elem(map, &key);

	/* This is a full L3/L4 match if port is not wildcarded,
	 * need to check for L4-only policy first if it is.
	 */
	if (likely(policy && !policy->wildcard_dport)) {
		cilium_dbg3(ctx, DBG_L4_CREATE, remote_id, local_id,
			    dport << 16 | proto);
		*match_type = POLICY_MATCH_L3_L4;		/* 1. id/proto/port */
		return __account_and_check(ctx, policy, ext_err, proxy_port);
	}

	/* L4-only lookup. */
	key.sec_label = 0;
	/* LPM precedence order without L3:
	 * 2. ANY/proto/port
	 * 4. ANY/proto/ANY
	 * 6. ANY/ANY/ANY   == allow-all as L3 is zeroed in this lookup,
	 *                     defer this until L3 match has been ruled out below.
	 *
	 * Untracked fragments always have zero ports in the tuple so they can
	 * only match entries that have fully wildcarded ports.
	 */
	l4policy = map_lookup_elem(map, &key);

	if (likely(l4policy && !l4policy->wildcard_dport)) {
		*match_type = POLICY_MATCH_L4_ONLY;		/* 2. ANY/proto/port */
		return __account_and_check(ctx, l4policy, ext_err, proxy_port);
	}

	if (likely(policy && !policy->wildcard_protocol)) {
		*match_type = POLICY_MATCH_L3_PROTO;		/* 3. id/proto/ANY */
		return __account_and_check(ctx, policy, ext_err, proxy_port);
	}

	if (likely(l4policy && !l4policy->wildcard_protocol)) {
		*match_type = POLICY_MATCH_PROTO_ONLY;		/* 4. ANY/proto/ANY */
		return __account_and_check(ctx, l4policy, ext_err, proxy_port);
	}

	if (likely(policy)) {
		*match_type = POLICY_MATCH_L3_ONLY;		/* 5. id/ANY/ANY */
		return __account_and_check(ctx, policy, ext_err, proxy_port);
	}

	if (likely(l4policy)) {
		*match_type = POLICY_MATCH_ALL;			/* 6. ANY/ANY/ANY */
		return __account_and_check(ctx, l4policy, ext_err, proxy_port);
	}

	/* TODO: Consider skipping policy lookup in this case? */
	if (ctx_load_meta(ctx, CB_POLICY)) {
		*proxy_port = 0;
		return CTX_ACT_OK;
	}

	if (is_untracked_fragment)
		return DROP_FRAG_NOSUPPORT;

	return DROP_POLICY;
}

/**
 * Determine whether the policy allows this traffic on ingress.
 * @arg ctx		Packet to allow or deny
 * @arg src_id		Source security identity for this packet
 * @arg dst_id		Destination security identity for this packet
 * @arg dport		Destination port of this packet
 * @arg proto		L3 Protocol of this packet
 * @arg is_untracked_fragment	True if packet is a TCP/UDP datagram fragment
 *				AND IPv4 fragment tracking is disabled
 * @arg match_type		Pointer to store layers used for policy match
 * @arg ext_err		Pointer to store extended error information if this packet isn't allowed
 *
 * Returns:
 *   - Positive integer indicating the proxy_port to handle this traffic
 *   - CTX_ACT_OK if the policy allows this traffic based only on labels/L3/L4
 *   - Negative error code if the packet should be dropped
 */
static __always_inline int
policy_can_access_ingress(struct __ctx_buff *ctx, __u32 src_id, __u32 dst_id,
			  __u16 dport, __u8 proto, bool is_untracked_fragment,
			  __u8 *match_type, __u8 *audited, __s8 *ext_err, __u16 *proxy_port)
{
	int ret;

	ret = __policy_can_access(&POLICY_MAP, ctx, dst_id, src_id, dport,
				  proto, CT_INGRESS, is_untracked_fragment,
				  match_type, ext_err, proxy_port);
	if (ret >= CTX_ACT_OK)
		return ret;

	cilium_dbg(ctx, DBG_POLICY_DENIED, src_id, dst_id);

	*audited = 0;
#ifdef POLICY_AUDIT_MODE
	if (IS_ERR(ret)) {
		ret = CTX_ACT_OK;
		*audited = 1;
	}
#endif

	return ret;
}

#ifdef HAVE_ENCAP
static __always_inline bool is_encap(__u16 dport, __u8 proto)
{
	return proto == IPPROTO_UDP && dport == bpf_htons(TUNNEL_PORT);
}
#endif

static __always_inline int
policy_can_egress(struct __ctx_buff *ctx, __u32 src_id, __u32 dst_id,
		  __u16 dport, __u8 proto, __u8 *match_type, __u8 *audited, __s8 *ext_err,
		  __u16 *proxy_port)
{
	int ret;

#ifdef HAVE_ENCAP
	if (src_id != HOST_ID && is_encap(dport, proto))
		return DROP_ENCAP_PROHIBITED;
#endif
	ret = __policy_can_access(&POLICY_MAP, ctx, src_id, dst_id, dport,
				  proto, CT_EGRESS, false, match_type, ext_err, proxy_port);
	if (ret >= 0)
		return ret;
	cilium_dbg(ctx, DBG_POLICY_DENIED, src_id, dst_id);
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
					      __u32 src_id, __u32 dst_id,
					      __u8 *match_type, __u8 *audited, __s8 *ext_err,
					      __u16 *proxy_port)
{
	return policy_can_egress(ctx, src_id, dst_id, tuple->dport,
				 tuple->nexthdr, match_type, audited, ext_err, proxy_port);
}

static __always_inline int policy_can_egress4(struct __ctx_buff *ctx,
					      const struct ipv4_ct_tuple *tuple,
					      __u32 src_id, __u32 dst_id,
					      __u8 *match_type, __u8 *audited, __s8 *ext_err,
					      __u16 *proxy_port)
{
	return policy_can_egress(ctx, src_id, dst_id, tuple->dport,
				 tuple->nexthdr, match_type, audited, ext_err, proxy_port);
}

/**
 * Mark ctx to skip policy enforcement
 * @arg ctx	packet
 *
 * Will cause the packet to ignore the policy enforcement verdict for allow rules and
 * be considered accepted despite of the policy outcome. Has no effect on deny rules.
 */
static __always_inline void policy_mark_skip(struct __ctx_buff *ctx)
{
	ctx_store_meta(ctx, CB_POLICY, 1);
}

static __always_inline void policy_clear_mark(struct __ctx_buff *ctx)
{
	ctx_store_meta(ctx, CB_POLICY, 0);
}
#endif
