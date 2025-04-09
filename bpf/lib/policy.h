/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/icmp.h>

#include "drop.h"
#include "dbg.h"
#include "eps.h"

/* Global policy stats map */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__type(key, struct policy_stats_key);
	__type(value, struct policy_stats_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_STATS_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);
} cilium_policystats __section_maps_btf;

/*
 * Both non-host and host EP programs have HOST_EP_ID defined, but only non-host EPs have LXC_ID
 * defined. Hence, if LXC_ID is defined, we are doing policy for a non-host EP, otherwise for the
 * host EP, or zero if neither is defined.
 */
#ifdef LXC_ID
#define EFFECTIVE_EP_ID LXC_ID
#elif defined(HOST_EP_ID)
#define EFFECTIVE_EP_ID HOST_EP_ID
#else
#define EFFECTIVE_EP_ID 0
#endif

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
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_policy_v2 __section_maps_btf;

static __always_inline int
__policy_check(struct policy_entry *policy, const struct policy_entry *policy2, __s8 *ext_err,
	       __u16 *proxy_port)
{
	/* auth_type is derived from the matched policy entry, except if both L3/L4 and L4-only
	 * match, and the chosen policy has no explicit auth type: in this case the auth type is
	 * derived from the less specific policy entry.
	 */
	__u8 auth_type;

	if (unlikely(policy->deny))
		return DROP_POLICY_DENY;

	/* The chosen 'policy' has higher proxy port priority or if on the same it has more
	 * specific L4 match, or if also the L4 are equally specific, then the chosen policy has
	 * an L3 match, which is considered to be more specific.
	 * If proxy port priority is the same, then by definition either both have a proxy
	 * redirect or neither has one, so we do not need to check if the other policy has a proxy
	 * redirect or not.
	 */
	*proxy_port = policy->proxy_port;

	auth_type = policy->auth_type;
	if (unlikely(policy2 && policy2->auth_type > auth_type &&
		     !policy->has_explicit_auth_type)) {
		/* Both L4-only and L3/4 policy matched, the chosen more specific one does not have
		 * an explicit auth type: Propagate the auth type from the more general policy if
		 * its (explicit or propagated) auth_type is greater than the propagated auth_type
		 * of the chosen policy (policy entry may have an auth_type propagated from another
		 * entry with en explicit auth type. Numerically greater value has precedence in
		 * that case).
		 */
		auth_type = policy2->auth_type;
	}

	if (unlikely(auth_type)) {
		if (ext_err)
			*ext_err = (__s8)auth_type;
		return DROP_POLICY_AUTH_REQUIRED;
	}
	return CTX_ACT_OK;
}

static __always_inline int
__policy_can_access(const void *map, struct __ctx_buff *ctx, __u32 local_id,
		    __u32 remote_id, __u16 ethertype __maybe_unused, __be16 dport,
		    __u8 proto, int off __maybe_unused, int dir,
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
	__u8 p_len;

#if defined(ALLOW_ICMP_FRAG_NEEDED) || defined(ENABLE_ICMP_RULE)
	switch (ethertype) {
	case ETH_P_IP:
		if (proto == IPPROTO_ICMP) {
			struct icmphdr icmphdr __align_stack_8;

			if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
				return DROP_INVALID;

# if defined(ALLOW_ICMP_FRAG_NEEDED)
			if (icmphdr.type == ICMP_DEST_UNREACH &&
			    icmphdr.code == ICMP_FRAG_NEEDED) {
				*proxy_port = 0;
				return CTX_ACT_OK;
			}
# endif

# if defined(ENABLE_ICMP_RULE)
			key.dport = bpf_u8_to_be16(icmphdr.type);
# endif
		}
		break;
	case ETH_P_IPV6:
# if defined(ENABLE_ICMP_RULE)
		if (proto == IPPROTO_ICMPV6) {
			__u8 icmp_type;

			if (ctx_load_bytes(ctx, off, &icmp_type, sizeof(icmp_type)) < 0)
				return DROP_INVALID;

			key.dport = bpf_u8_to_be16(icmp_type);
		}
# endif
		break;
	default:
		break;
	}
#endif /* ALLOW_ICMP_FRAG_NEEDED || ENABLE_ICMP_RULE */

	/* Policy match precedence when both L3 and L4-only lookups find a matching policy:

	 * 1. Deny policy, if any, is selected.
	 * 2. Policy with higher proxy port pririty is selected. This includes giving precedence
	 *    to proxy redirect over non-proxy redirect, and proxy port priority.
	 * 3. The entry with longer prefix length is selected out of the two allow entries.
	 * 4. Otherwise the allow entry with non-wildcard L3 is chosen.
	 */

	/* Note: Untracked fragments always have zero ports in the tuple so they can
	 * only match entries that have fully wildcarded ports.
	 */

	/* L3 lookup: an exact match on L3 identity and LPM match on L4 proto and port. */
	policy = map_lookup_elem(map, &key);

	/* L3 policy can be chosen without the 2nd lookup if it is a deny. */
	if (likely(policy && policy->deny)) {
		l4policy = NULL;
		goto check_policy;
	}

	/* L4-only lookup: a wildcard match on L3 identity and LPM match on L4 proto and port. */
	key.sec_label = 0;
	l4policy = map_lookup_elem(map, &key);

	/* The found l4policy is chosen if:
	 * - only l4 policy was found, or if both policies are found, and:
	 * 1. It is a deny policy, or
	 * 2. proxy port priority is equal and L4-only policy has longer LPM prefix length
	 *    than the L3 policy
	 */
	if (l4policy &&
	    (l4policy->deny || !policy ||
	     l4policy->proxy_port_priority > policy->proxy_port_priority ||
	     (l4policy->proxy_port_priority == policy->proxy_port_priority &&
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
#ifdef POLICY_ACCOUNTING
	__policy_account(remote_id, key.egress, proto, dport, p_len, ctx_full_len(ctx));
#endif
	*match_type =
		p_len > LPM_PROTO_PREFIX_BITS ? POLICY_MATCH_L3_L4 :	/* 1. id/proto/port */
		p_len > 0 ? POLICY_MATCH_L3_PROTO :			/* 3. id/proto/ANY */
		POLICY_MATCH_L3_ONLY;					/* 5. id/ANY/ANY */
	return __policy_check(policy, l4policy, ext_err, proxy_port);

check_l4_policy:
	p_len = l4policy->lpm_prefix_length;
#ifdef POLICY_ACCOUNTING
	__policy_account(0, key.egress, proto, dport, p_len, ctx_full_len(ctx));
#endif
	*match_type =
		p_len == 0 ? POLICY_MATCH_ALL :					/* 6. ANY/ANY/ANY */
		p_len <= LPM_PROTO_PREFIX_BITS ? POLICY_MATCH_PROTO_ONLY :	/* 4. ANY/proto/ANY */
		POLICY_MATCH_L4_ONLY;						/* 2. ANY/proto/port */
	return __policy_check(l4policy, policy, ext_err, proxy_port);
}

/**
 * Determine whether the policy allows this traffic on ingress.
 * @arg ctx		Packet to allow or deny
 * @arg map		Policy map
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
 *
 * Returns:
 *   - Positive integer indicating the proxy_port to handle this traffic
 *   - CTX_ACT_OK if the policy allows this traffic based only on labels/L3/L4
 *   - Negative error code if the packet should be dropped
 */
static __always_inline int
policy_can_ingress(struct __ctx_buff *ctx, const void *map, __u32 src_id, __u32 dst_id,
		   __u16 ethertype, __be16 dport, __u8 proto, int l4_off,
		   bool is_untracked_fragment, __u8 *match_type, __u8 *audited,
		   __s8 *ext_err, __u16 *proxy_port)
{
	int ret;

	ret = __policy_can_access(map, ctx, dst_id, src_id, ethertype, dport,
				  proto, l4_off, CT_INGRESS, is_untracked_fragment,
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

static __always_inline int policy_can_ingress6(struct __ctx_buff *ctx, const void *map,
					       const struct ipv6_ct_tuple *tuple,
					       int l4_off, bool is_untracked_fragment,
					       __u32 src_id, __u32 dst_id,
					       __u8 *match_type, __u8 *audited,
					       __s8 *ext_err, __u16 *proxy_port)
{
	return policy_can_ingress(ctx, map, src_id, dst_id, ETH_P_IPV6, tuple->dport,
				 tuple->nexthdr, l4_off, is_untracked_fragment,
				 match_type, audited, ext_err, proxy_port);
}

static __always_inline int policy_can_ingress4(struct __ctx_buff *ctx,
		const void *map,
					       const struct ipv4_ct_tuple *tuple,
					       int l4_off, bool is_untracked_fragment,
					       __u32 src_id, __u32 dst_id,
					       __u8 *match_type, __u8 *audited,
					       __s8 *ext_err, __u16 *proxy_port)
{
	return policy_can_ingress(ctx, map, src_id, dst_id, ETH_P_IP, tuple->dport,
				 tuple->nexthdr, l4_off, is_untracked_fragment,
				 match_type, audited, ext_err, proxy_port);
}

#ifdef HAVE_ENCAP
static __always_inline bool is_encap(__be16 dport, __u8 proto)
{
	return proto == IPPROTO_UDP && dport == bpf_htons(TUNNEL_PORT);
}
#endif

static __always_inline int
policy_can_egress(struct __ctx_buff *ctx, const void *map, __u32 src_id, __u32 dst_id,
		  __u16 ethertype, __be16 dport, __u8 proto, int l4_off, __u8 *match_type,
		  __u8 *audited, __s8 *ext_err, __u16 *proxy_port)
{
	int ret;

#ifdef HAVE_ENCAP
	if (src_id != HOST_ID && is_encap(dport, proto))
		return DROP_ENCAP_PROHIBITED;
#endif
	ret = __policy_can_access(map, ctx, src_id, dst_id, ethertype, dport,
				  proto, l4_off, CT_EGRESS, false, match_type,
				  ext_err, proxy_port);
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

static __always_inline int policy_can_egress6(struct __ctx_buff *ctx, const void *map,
					      const struct ipv6_ct_tuple *tuple,
					      int l4_off, __u32 src_id, __u32 dst_id,
					      __u8 *match_type, __u8 *audited, __s8 *ext_err,
					      __u16 *proxy_port)
{
	return policy_can_egress(ctx, map, src_id, dst_id, ETH_P_IPV6, tuple->dport,
				 tuple->nexthdr, l4_off, match_type, audited,
				 ext_err, proxy_port);
}

static __always_inline int policy_can_egress4(struct __ctx_buff *ctx, const void *map,
					      const struct ipv4_ct_tuple *tuple,
					      int l4_off, __u32 src_id, __u32 dst_id,
					      __u8 *match_type, __u8 *audited, __s8 *ext_err,
					      __u16 *proxy_port)
{
	return policy_can_egress(ctx, map, src_id, dst_id, ETH_P_IP, tuple->dport,
				 tuple->nexthdr, l4_off, match_type, audited,
				 ext_err, proxy_port);
}
