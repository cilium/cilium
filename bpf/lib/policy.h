/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/icmp.h>

#include "common.h"
#include "dbg.h"

DECLARE_CONFIG(bool, allow_icmp_frag_needed,
	       "Allow ICMP_FRAG_NEEDED messages when applying Network Policy")
DECLARE_CONFIG(bool, enable_icmp_rule, "Apply Network Policy for ICMP packets")
DECLARE_CONFIG(bool, enable_policy_accounting,
	       "Maintain packet and byte counters for every policy entry")


#ifndef EFFECTIVE_EP_ID
#define EFFECTIVE_EP_ID 0
#endif

enum {
	POLICY_INGRESS = 1,
	POLICY_EGRESS = 2,
};

enum {
	POLICY_MATCH_NONE = 0,
	POLICY_MATCH_L3_ONLY = 1,
	POLICY_MATCH_L3_L4 = 2,
	POLICY_MATCH_L4_ONLY = 3,
	POLICY_MATCH_ALL = 4,
	POLICY_MATCH_L3_PROTO = 5,
	POLICY_MATCH_PROTO_ONLY = 6,
};

/*
 * Longest-prefix match map lookup only matches the number of bits from the
 * beginning of the key stored in the map indicated by the 'lpm_key' field in
 * the same stored map key, not including the 'lpm_key' field itself. Note that
 * the 'lpm_key' value passed in the lookup function argument needs to be a
 * "full prefix" (POLICY_FULL_PREFIX defined below).
 *
 * Since we need to be able to wildcard 'sec_label' independently on 'protocol'
 * and 'dport' fields, we'll need to do that explicitly with a separate lookup
 * where 'sec_label' is zero. For the 'protocol' and 'port' we can use the
 * longest-prefix match by placing them at the end ot the key in this specific
 * order, as we want to be able to wildcard those fields in a specific pattern:
 * 'protocol' can only be wildcarded if dport is also fully wildcarded.
 * 'protocol' is never partially wildcarded, so it is either fully wildcarded or
 * not wildcarded at all. 'dport' can be partially wildcarded, but only when
 * 'protocol' is fully specified. This follows the logic that the destination
 * port is a property of a transport protocol and can not be specified without
 * also specifying the protocol.
 */
struct policy_key {
	struct bpf_lpm_trie_key lpm_key;
	__u32		sec_label;
	__u8		egress:1,
			pad:7;
	__u8		protocol; /* can be wildcarded if 'dport' is fully wildcarded */
	__be16		dport; /* can be wildcarded with CIDR-like prefix */
};

/* POLICY_FULL_PREFIX gets full prefix length of policy_key */
#define POLICY_FULL_PREFIX						\
  (8 * (sizeof(struct policy_key) - sizeof(struct bpf_lpm_trie_key)))

struct policy_entry {
	__be16		proxy_port;
	__u8		deny:1,
			reserved:2, /* bits used in Cilium 1.16, keep unused for Cilium 1.17 */
			lpm_prefix_length:5; /* map key protocol and dport prefix length */
	__u8		auth_type:7,
			has_explicit_auth_type:1;
	__u32		precedence;
	__u32		cookie;
};

/*
 * LPM_FULL_PREFIX_BITS is the maximum length in 'lpm_prefix_length' when none of the protocol or
 * dport bits in the key are wildcarded.
 */
#define LPM_PROTO_PREFIX_BITS 8                             /* protocol specified */
#define LPM_FULL_PREFIX_BITS (LPM_PROTO_PREFIX_BITS + 16)   /* protocol and dport specified */

/* Highest possible precedence */
#define MAX_PRECEDENCE (~0U)

/*
 * policy_stats_key has the same layout as policy_key, apart from the first four bytes.
 */
struct policy_stats_key {
	__u16		endpoint_id;
	__u8		pad1;
	__u8		prefix_len;
	__u32		sec_label;
	__u8		egress:1,
			pad:7;
	__u8		protocol; /* can be wildcarded if 'dport' is fully wildcarded */
	__be16		dport; /* can be wildcarded with CIDR-like prefix */
};

struct policy_stats_value {
	__u64		packets;
	__u64		bytes;
};

/* Global policy stats map */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__type(key, struct policy_stats_key);
	__type(value, struct policy_stats_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_STATS_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);
} cilium_policystats __section_maps_btf;

static __always_inline void
__policy_account(__u32 remote_id, __u8 egress, __u8 proto, __be16 dport, __u8 lpm_prefix_length,
		 __u64 bytes)
{
	struct policy_stats_value *value;
	struct policy_stats_key stats_key = {
		.endpoint_id = EFFECTIVE_EP_ID,
		.pad1 = 0,
		.prefix_len = lpm_prefix_length,
		.sec_label = remote_id,
		.egress = egress,
		.pad = 0,
	};

	/*
	 * Must compute the wildcarded protocol and port for the policy stats map key.
	 * If bpf lookup ever returned the key of the matching entry we would not need
	 * to do this.
	 */
	if (lpm_prefix_length <= LPM_PROTO_PREFIX_BITS) {
		if (lpm_prefix_length < LPM_PROTO_PREFIX_BITS) {
			/* Protocol is not partially maskable */
			proto = 0;
		}
		dport = 0;
	} else if (lpm_prefix_length < LPM_FULL_PREFIX_BITS) {
		dport &= bpf_htons((__u16)(0xffff << (LPM_FULL_PREFIX_BITS - lpm_prefix_length)));
	}
	stats_key.protocol = proto;
	stats_key.dport = dport;

	value = map_lookup_elem(&cilium_policystats, &stats_key);

	if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, bytes);
	} else {
		struct policy_stats_value newval = { 1, bytes };

		map_update_elem(&cilium_policystats, &stats_key, &newval, BPF_NOEXIST);
	}
}

/* Per-endpoint policy enforcement map */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct policy_key);
	__type(value, struct policy_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_policy_v2 __section_maps_btf;

/* Return a verdict for the chosen 'policy', possibly propagating the auth type from 'policy2', if
 * non-NULL and of the same precedence.
 *
 * Always called with non-NULL 'policy', while 'policy2' may be NULL.
 * If 'policy2' is non-null, it never has a higher precedence than 'policy'.
 */
static __always_inline int
__policy_check(const struct policy_entry *policy, const struct policy_entry *policy2, __s8 *ext_err,
	       __u16 *proxy_port, __u32 *cookie)
{
	/* auth_type is derived from the matched policy entry, except if both L3/L4 and L4-only
	 * match, and the chosen policy has no explicit auth type: in this case the auth type is
	 * derived from the less specific policy entry.
	 */
	__u8 auth_type;

	*cookie = policy->cookie;

	if (unlikely(policy->deny))
		return DROP_POLICY_DENY;

	/* The chosen 'policy' has higher precedence or if on the same precedence it has more
	 * specific L4 match, or if also the L4 are equally specific, then the chosen policy has
	 * an L3 match, which is considered to be more specific.
	 * If precedence is the same, then by definition either both have a proxy
	 * redirect or neither has one, so we do not need to check if the other policy has a proxy
	 * redirect or not.
	 */
	*proxy_port = policy->proxy_port;

	auth_type = policy->auth_type;
	/* Propagate the auth type from the same precedence, more general policy2 if needed. */
	if (unlikely(policy2 && policy2->precedence == policy->precedence &&
		     !policy->has_explicit_auth_type && policy2->auth_type > auth_type)) {
		auth_type = policy2->auth_type;
	}

	if (unlikely(auth_type)) {
		if (ext_err)
			*ext_err = (__s8)auth_type;
		return DROP_POLICY_AUTH_REQUIRED;
	}
	return CTX_ACT_OK;
}

/* Allow experimental access to the @map parameter. */
static __always_inline int
__policy_can_access(const void *map, struct __ctx_buff *ctx, __u32 local_id,
		    __u32 remote_id, __u16 ethertype, __be16 dport, __u8 proto,
		    int off, int dir, bool is_untracked_fragment,
		    __u8 *match_type, __s8 *ext_err, __u16 *proxy_port,
		    __u32 *cookie)
{
	const struct policy_entry *policy;
	const struct policy_entry *l4policy;
	struct policy_key key = {
		.lpm_key = { POLICY_FULL_PREFIX, {} }, /* always look up with unwildcarded data */
		.sec_label = remote_id,
		.egress = !dir,
		.pad = 0,
		.protocol = proto,
		.dport = dport,
	};
	__u8 p_len;

	if (CONFIG(allow_icmp_frag_needed) || CONFIG(enable_icmp_rule)) {
		switch (ethertype) {
		case ETH_P_IP:
			if (proto == IPPROTO_ICMP) {
				struct icmphdr icmphdr __align_stack_8;

				if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
					return DROP_INVALID;

				if (CONFIG(allow_icmp_frag_needed)) {
					if (icmphdr.type == ICMP_DEST_UNREACH &&
					    icmphdr.code == ICMP_FRAG_NEEDED) {
						*proxy_port = 0;
						return CTX_ACT_OK;
					}
				}

				if (CONFIG(enable_icmp_rule))
					key.dport = bpf_u8_to_be16(icmphdr.type);
			}
			break;
		case ETH_P_IPV6:
			if (CONFIG(enable_icmp_rule)) {
				if (proto == IPPROTO_ICMPV6) {
					__u8 icmp_type;

					if (ctx_load_bytes(ctx, off, &icmp_type,
							   sizeof(icmp_type)) < 0)
						return DROP_INVALID;

					key.dport = bpf_u8_to_be16(icmp_type);
				}
			}
			break;
		default:
			break;
		}
	}

	/* Policy match precedence when both L3 and L4-only lookups find a matching policy:
	 *
	 * 1. Policy with the higher precedence value is selected. This includes giving precedence
	 *    to deny over allow, proxy redirect over non-proxy redirect, and proxy port priority.
	 * 2. The entry with longer prefix length is selected out of the two entries with the same
	 *    precedence.
	 * 3. Otherwise the allow entry with non-wildcard L3 is chosen.
	 */

	/* Note: Untracked fragments always have zero ports in the tuple so they can
	 * only match entries that have fully wildcarded ports.
	 */

	/* L3 lookup: an exact match on L3 identity and LPM match on L4 proto and port. */
	policy = map_lookup_elem(map, &key);

	/* L3 policy can be chosen without the 2nd lookup if it has the highest possible precedence
	 * value (which implies that it is a deny).
	 */
	if (likely(policy && policy->precedence == MAX_PRECEDENCE)) {
		l4policy = NULL;
		goto check_policy;
	}

	/* L4-only lookup: a wildcard match on L3 identity and LPM match on L4 proto and port. */
	key.sec_label = 0;
	l4policy = map_lookup_elem(map, &key);

	/* The found l4policy is chosen if:
	 * - only l4 policy was found, or if both policies are found, and:
	 * 1. It has higher precedence value, or
	 * 2. Precedence is equal (which implies both are denys or both are allows) and
	 *    L4-only policy has longer LPM prefix length than the L3 policy
	 */
	if (l4policy &&
	    (!policy ||
	     l4policy->precedence > policy->precedence ||
	     (l4policy->precedence == policy->precedence &&
	      l4policy->lpm_prefix_length > policy->lpm_prefix_length)))
		goto check_l4_policy;

	/* 4. Otherwise select L3 policy if found. */
	if (likely(policy))
		goto check_policy;

	if (is_untracked_fragment)
		return DROP_FRAG_NOSUPPORT;

	return DROP_POLICY;

check_policy:
	cilium_dbg3(ctx, DBG_L4_CREATE, remote_id, local_id, dport << 16 | proto);
	p_len = policy->lpm_prefix_length;
	if (CONFIG(enable_policy_accounting))
		__policy_account(remote_id, key.egress, proto, dport, p_len, ctx_full_len(ctx));

	*match_type =
		p_len > LPM_PROTO_PREFIX_BITS ? POLICY_MATCH_L3_L4 :	/* 1. id/proto/port */
		p_len > 0 ? POLICY_MATCH_L3_PROTO :			/* 3. id/proto/ANY */
		POLICY_MATCH_L3_ONLY;					/* 5. id/ANY/ANY */
	return __policy_check(policy, l4policy, ext_err, proxy_port, cookie);

check_l4_policy:
	p_len = l4policy->lpm_prefix_length;
	if (CONFIG(enable_policy_accounting))
		__policy_account(0, key.egress, proto, dport, p_len, ctx_full_len(ctx));

	*match_type =
		p_len == 0 ? POLICY_MATCH_ALL :					/* 6. ANY/ANY/ANY */
		p_len <= LPM_PROTO_PREFIX_BITS ? POLICY_MATCH_PROTO_ONLY :	/* 4. ANY/proto/ANY */
		POLICY_MATCH_L4_ONLY;						/* 2. ANY/proto/port */
	return __policy_check(l4policy, policy, ext_err, proxy_port, cookie);
}

static __always_inline int
policy_can_access(struct __ctx_buff *ctx, __u32 local_id, __u32 remote_id,
		  __u16 ethertype, __be16 dport, __u8 proto, int off, int dir,
		  bool is_untracked_fragment, __u8 *match_type, __s8 *ext_err,
		  __u16 *proxy_port, __u32 *cookie)
{
	return __policy_can_access(&cilium_policy_v2, ctx, local_id, remote_id,
				   ethertype, dport, proto, off, dir,
				   is_untracked_fragment, match_type, ext_err,
				   proxy_port, cookie);
}

/**
 * Determine whether the policy allows this traffic on ingress.
 * @arg ctx		Packet to allow or deny
 * @arg src_id		Source security identity for this packet
 * @arg dst_id		Destination security identity for this packet
 * @arg ethertype	Ethertype of this packet
 * @arg dport		Destination port of this packet
 * @arg proto		L3 Protocol of this packet
 * @arg l4_off		Offset to L4 header of this packet
 * @arg is_untracked_fragment	True if packet is a TCP/UDP datagram fragment
 *				AND IPv4 fragment tracking is disabled
 * @arg match_type		Pointer to store layers used for policy match
 * @arg ext_err		Pointer to store extended error information if this packet isn't allowed
 * @arg proxy_port	Pointer to store port for proxy redirect
 * @arg cookie		Pointer to store policy log cookie, if any
 *
 * Returns:
 *   - Positive integer indicating the proxy_port to handle this traffic
 *   - CTX_ACT_OK if the policy allows this traffic based only on labels/L3/L4
 *   - Negative error code if the packet should be dropped
 */
static __always_inline int
policy_can_ingress(struct __ctx_buff *ctx, __u32 src_id, __u32 dst_id,
		   __u16 ethertype, __be16 dport, __u8 proto, int l4_off,
		   bool is_untracked_fragment, __u8 *match_type, __u8 *audited,
		   __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	int ret;

	ret = policy_can_access(ctx, dst_id, src_id, ethertype, dport,
				proto, l4_off, CT_INGRESS, is_untracked_fragment,
				match_type, ext_err, proxy_port, cookie);
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

static __always_inline int policy_can_ingress6(struct __ctx_buff *ctx,
					       const struct ipv6_ct_tuple *tuple,
					       int l4_off, bool is_untracked_fragment,
					       __u32 src_id, __u32 dst_id,
					       __u8 *match_type, __u8 *audited,
					       __s8 *ext_err, __u16 *proxy_port,
					       __u32 *cookie)
{
	return policy_can_ingress(ctx, src_id, dst_id, ETH_P_IPV6, tuple->dport,
				 tuple->nexthdr, l4_off, is_untracked_fragment,
				 match_type, audited, ext_err, proxy_port, cookie);
}

static __always_inline int policy_can_ingress4(struct __ctx_buff *ctx,
					       const struct ipv4_ct_tuple *tuple,
					       int l4_off, bool is_untracked_fragment,
					       __u32 src_id, __u32 dst_id,
					       __u8 *match_type, __u8 *audited,
					       __s8 *ext_err, __u16 *proxy_port,
					       __u32 *cookie)
{
	return policy_can_ingress(ctx, src_id, dst_id, ETH_P_IP, tuple->dport,
				 tuple->nexthdr, l4_off, is_untracked_fragment,
				 match_type, audited, ext_err, proxy_port, cookie);
}

#ifdef HAVE_ENCAP
static __always_inline bool is_encap(__be16 dport, __u8 proto)
{
	return proto == IPPROTO_UDP && dport == bpf_htons(CONFIG(tunnel_port));
}
#endif

static __always_inline int
policy_can_egress(struct __ctx_buff *ctx, __u32 src_id, __u32 dst_id,
		  __u16 ethertype, __be16 dport, __u8 proto, int l4_off, __u8 *match_type,
		  __u8 *audited, __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	int ret;

#ifdef HAVE_ENCAP
	if (src_id != HOST_ID && is_encap(dport, proto))
		return DROP_ENCAP_PROHIBITED;
#endif
	ret = policy_can_access(ctx, src_id, dst_id, ethertype, dport,
				proto, l4_off, CT_EGRESS, false, match_type,
				ext_err, proxy_port, cookie);
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
					      int l4_off, __u32 src_id, __u32 dst_id,
					      __u8 *match_type, __u8 *audited, __s8 *ext_err,
					      __u16 *proxy_port, __u32 *cookie)
{
	return policy_can_egress(ctx, src_id, dst_id, ETH_P_IPV6, tuple->dport,
				 tuple->nexthdr, l4_off, match_type, audited,
				 ext_err, proxy_port, cookie);
}

static __always_inline int policy_can_egress4(struct __ctx_buff *ctx,
					      const struct ipv4_ct_tuple *tuple,
					      int l4_off, __u32 src_id, __u32 dst_id,
					      __u8 *match_type, __u8 *audited, __s8 *ext_err,
					      __u16 *proxy_port, __u32 *cookie)
{
	return policy_can_egress(ctx, src_id, dst_id, ETH_P_IP, tuple->dport,
				 tuple->nexthdr, l4_off, match_type, audited,
				 ext_err, proxy_port, cookie);
}
