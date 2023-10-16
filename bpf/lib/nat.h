/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Simple NAT engine in BPF. */
#ifndef __LIB_NAT__
#define __LIB_NAT__

#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>

#include "bpf/compiler.h"
#include "common.h"
#include "drop.h"
#include "signal.h"
#include "conntrack.h"
#include "conntrack_map.h"
#include "egress_gateway.h"
#include "icmp6.h"
#include "nat_46x64.h"
#include "stubs.h"
#include "trace.h"

enum  nat_dir {
	NAT_DIR_EGRESS  = TUPLE_F_OUT,
	NAT_DIR_INGRESS = TUPLE_F_IN,
} __packed;

struct nat_entry {
	__u64 created;
	__u64 needs_ct;		/* Only single bit used. */
	__u64 pad1;		/* Future use. */
	__u64 pad2;		/* Future use. */
};

#ifdef HAVE_LARGE_INSN_LIMIT
# define SNAT_COLLISION_RETRIES		128
# define SNAT_SIGNAL_THRES		64
#else
# define SNAT_COLLISION_RETRIES		32
# define SNAT_SIGNAL_THRES		16
#endif

static __always_inline __u16 __snat_clamp_port_range(__u16 start, __u16 end,
						     __u16 val)
{
	return (val % (__u16)(end - start)) + start;
}

static __always_inline __maybe_unused __u16
__snat_try_keep_port(__u16 start, __u16 end, __u16 val)
{
	return val >= start && val <= end ? val :
	       __snat_clamp_port_range(start, end, (__u16)get_prandom_u32());
}

static __always_inline __maybe_unused void *
__snat_lookup(const void *map, const void *tuple)
{
	return map_lookup_elem(map, tuple);
}

static __always_inline __maybe_unused int
__snat_update(const void *map, const void *otuple, const void *ostate,
	      const void *rtuple, const void *rstate)
{
	int ret;

	ret = map_update_elem(map, rtuple, rstate, BPF_NOEXIST);
	if (!ret) {
		ret = map_update_elem(map, otuple, ostate, BPF_NOEXIST);
		if (ret)
			map_delete_elem(map, rtuple);
	}
	return ret;
}

struct ipv4_nat_entry {
	struct nat_entry common;
	union {
		struct lb4_reverse_nat nat_info;
		struct {
			__be32 to_saddr;
			__be16 to_sport;
		};
		struct {
			__be32 to_daddr;
			__be16 to_dport;
		};
	};
};

struct ipv4_nat_target {
	__be32 addr;
	const __u16 min_port; /* host endianness */
	const __u16 max_port; /* host endianness */
	bool from_local_endpoint;
	bool egress_gateway; /* NAT is needed because of an egress gateway policy */
	__u32 cluster_id;
	bool needs_ct;
};

#if defined(ENABLE_IPV4) && defined(ENABLE_NODEPORT)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ipv4_nat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SNAT_MAPPING_IPV4_SIZE);
} SNAT_MAPPING_IPV4 __section_maps_btf;

#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
struct per_cluster_snat_mapping_ipv4_inner_map {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ipv4_nat_entry);
	__uint(max_entries, SNAT_MAPPING_IPV4_SIZE);
#ifndef BPF_TEST
};
#else
} per_cluster_snat_mapping_ipv4_1 __section_maps_btf,
  per_cluster_snat_mapping_ipv4_2 __section_maps_btf;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 256);
	__array(values, struct per_cluster_snat_mapping_ipv4_inner_map);
#ifndef BPF_TEST
} PER_CLUSTER_SNAT_MAPPING_IPV4 __section_maps_btf;
#else
} PER_CLUSTER_SNAT_MAPPING_IPV4 __section_maps_btf = {
	.values = {
		[1] = &per_cluster_snat_mapping_ipv4_1,
		[2] = &per_cluster_snat_mapping_ipv4_2,
	},
};
#endif
#endif

#ifdef ENABLE_IP_MASQ_AGENT_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v4_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} IP_MASQ_AGENT_IPV4 __section_maps_btf;
#endif

static __always_inline void *
get_cluster_snat_map_v4(__u32 cluster_id __maybe_unused)
{
#if defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && defined(ENABLE_INTER_CLUSTER_SNAT)
	if (cluster_id != 0 && cluster_id != CLUSTER_ID)
		return map_lookup_elem(&PER_CLUSTER_SNAT_MAPPING_IPV4, &cluster_id);
#endif
	return &SNAT_MAPPING_IPV4;
}

static __always_inline
struct ipv4_nat_entry *snat_v4_lookup(const struct ipv4_ct_tuple *tuple)
{
	return __snat_lookup(&SNAT_MAPPING_IPV4, tuple);
}

static __always_inline int snat_v4_new_mapping(struct __ctx_buff *ctx, void *map,
					       struct ipv4_ct_tuple *otuple,
					       struct ipv4_nat_entry *ostate,
					       const struct ipv4_nat_target *target,
					       bool needs_ct, __s8 *ext_err)
{
	struct ipv4_ct_tuple rtuple = {};
	struct ipv4_nat_entry rstate;
	int ret, retries;
	__u16 port;

	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;
	/* .to_sport is selected below */

	/* This tuple matches reply traffic for the SNATed connection: */
	rtuple.flags = TUPLE_F_IN;
	rtuple.nexthdr = otuple->nexthdr;
	rtuple.saddr = otuple->daddr;
	rtuple.daddr = ostate->to_saddr;
	rtuple.sport = otuple->dport;
	/* .dport is selected below */

	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	ostate->common.needs_ct = needs_ct;
	rstate.common.needs_ct = needs_ct;

#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		rtuple.dport = bpf_htons(port);

		/* Check if the selected port is already in use by a RevSNAT
		 * entry for some other connection with the same src/dst:
		 */
		if (!__snat_lookup(map, &rtuple))
			goto create_nat_entries;

		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
	}

	/* Loop completed without finding a free port: */
	ret = DROP_NAT_NO_MAPPING;
	goto out;

create_nat_entries:
	ostate->to_sport = rtuple.dport;
	ostate->common.created = bpf_mono_now();
	rstate.common.created = ostate->common.created;

	/* Create the SNAT and RevSNAT entries. We just confirmed that
	 * this RevSNAT entry doesn't exist yet, and the caller previously
	 * checked that no SNAT entry for this connection exists.
	 */
	ret = __snat_update(map, otuple, ostate, &rtuple, &rstate);
	if (ret < 0) {
		if (ext_err)
			*ext_err = (__s8)ret;
		ret = DROP_NAT_NO_MAPPING;
	}

out:
	/* We struggled to find a free port. Trigger GC in the agent to
	 * free up any ports that are held by expired connections.
	 */
	if (retries > SNAT_SIGNAL_THRES)
		send_signal_nat_fill_up(ctx, SIGNAL_PROTO_V4);

	return ret;
}

static __always_inline int
snat_v4_nat_handle_mapping(struct __ctx_buff *ctx,
			   struct ipv4_ct_tuple *tuple,
			   bool has_l4_header,
			   struct ipv4_nat_entry **state,
			   struct ipv4_nat_entry *tmp,
			   struct iphdr *ip4, __u32 off,
			   const struct ipv4_nat_target *target,
			   struct trace_ctx *trace,
			   __s8 *ext_err)
{
	bool needs_ct = target->needs_ct;
	void *map;

	map = get_cluster_snat_map_v4(target->cluster_id);
	if (!map)
		return DROP_SNAT_NO_MAP_FOUND;

	*state = __snat_lookup(map, tuple);

	if (needs_ct) {
		struct ipv4_ct_tuple tuple_snat;
		struct ct_state ct_state = {};
		int ret;

		memcpy(&tuple_snat, tuple, sizeof(tuple_snat));
		/* Lookup with SCOPE_FORWARD. Ports are already in correct layout: */
		ipv4_ct_tuple_swap_addrs(&tuple_snat);

		ret = ct_lazy_lookup4(get_ct_map4(&tuple_snat), &tuple_snat,
				      ctx, ipv4_is_fragment(ip4), off, has_l4_header,
				      CT_EGRESS, SCOPE_FORWARD, CT_ENTRY_ANY,
				      &ct_state, &trace->monitor);
		if (ret < 0)
			return ret;

		trace->reason = (enum trace_reason)ret;
		if (ret == CT_NEW) {
			ret = ct_create4(get_ct_map4(&tuple_snat), NULL,
					 &tuple_snat, ctx, CT_EGRESS,
					 &ct_state, false, false, ext_err);
			if (IS_ERR(ret))
				return ret;
		}
	}

	if (*state)
		return 0;
	else
		return snat_v4_new_mapping(ctx, map, tuple, (*state = tmp),
					   target, needs_ct, ext_err);
}

static __always_inline int
snat_v4_rev_nat_handle_mapping(struct __ctx_buff *ctx,
			       struct ipv4_ct_tuple *tuple,
			       bool has_l4_header,
			       struct ipv4_nat_entry **state,
			       struct iphdr *ip4, __u32 off,
			       const struct ipv4_nat_target *target,
			       struct trace_ctx *trace)
{
	void *map;

	map = get_cluster_snat_map_v4(target->cluster_id);
	if (!map)
		return DROP_SNAT_NO_MAP_FOUND;

	*state = __snat_lookup(map, tuple);

	if (*state && (*state)->common.needs_ct) {
		struct ipv4_ct_tuple tuple_revsnat;
		struct ct_state ct_state = {};
		int ret;

		memcpy(&tuple_revsnat, tuple, sizeof(tuple_revsnat));
		tuple_revsnat.daddr = (*state)->to_daddr;
		tuple_revsnat.dport = (*state)->to_dport;

		/* CT expects a tuple with the source and destination ports reversed,
		 * while NAT uses normal tuples that match packet headers.
		 */
		ipv4_ct_tuple_swap_ports(&tuple_revsnat);

		ret = ct_lazy_lookup4(get_ct_map4(&tuple_revsnat), &tuple_revsnat,
				      ctx, ipv4_is_fragment(ip4), off, has_l4_header,
				      CT_INGRESS, SCOPE_REVERSE, CT_ENTRY_ANY,
				      &ct_state, &trace->monitor);
		if (ret < 0)
			return ret;

		trace->reason = (enum trace_reason)ret;
	}

	if (*state)
		return 0;

	return DROP_NAT_NO_MAPPING;
}

static __always_inline int
snat_v4_rewrite_headers(struct __ctx_buff *ctx, __u8 nexthdr, int l3_off,
			bool has_l4_header, int l4_off,
			__be32 old_addr, __be32 new_addr, __u16 addr_off,
			__be16 old_port, __be16 new_port, __u16 port_off)
{
	__wsum sum;
	int err;

	/* No change needed: */
	if (old_addr == new_addr && old_port == new_port)
		return 0;

	sum = csum_diff(&old_addr, 4, &new_addr, 4, 0);
	if (ctx_store_bytes(ctx, l3_off + addr_off, &new_addr, 4, 0) < 0)
		return DROP_WRITE_ERROR;

	if (has_l4_header) {
		int flags = BPF_F_PSEUDO_HDR;
		struct csum_offset csum = {};

		csum_l4_offset_and_flags(nexthdr, &csum);

		if (old_port != new_port) {
			switch (nexthdr) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				break;
#ifdef ENABLE_SCTP
			case IPPROTO_SCTP:
				return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
			case IPPROTO_ICMP:
				/* Not initialized by csum_l4_offset_and_flags(), because ICMPv4
				 * doesn't use a pseudo-header, and the change in IP addresses is
				 * not supposed to change the L4 checksum.
				 * Set it temporarily to amend the checksum after changing ports.
				 */
				csum.offset = offsetof(struct icmphdr, checksum);
				break;
			default:
				return DROP_UNKNOWN_L4;
			}

			/* Amend the L4 checksum due to changing the ports. */
			err = l4_modify_port(ctx, l4_off, port_off, &csum, new_port, old_port);
			if (err < 0)
				return err;

			/* Restore the original offset. */
			if (nexthdr == IPPROTO_ICMP)
				csum.offset = 0;
		}

		/* Amend the L4 checksum due to changing the addresses. */
		if (csum.offset &&
		    csum_l4_replace(ctx, l4_off, &csum, 0, sum, flags) < 0)
			return DROP_CSUM_L4;
	}

	/* Amend the L3 checksum due to changing the addresses. */
	if (ipv4_csum_update_by_diff(ctx, l3_off, sum) < 0)
		return DROP_CSUM_L3;

	return 0;
}

/* NAT dest of the inner IP and L4 header of the ICMP packet.
 * It's like SNAT (endpoint -> host) but on the dest because
 * the inner packets are sent from remote to endpoint.
 */
static __always_inline int
snat_v4_icmp_rewrite_egress_embedded(struct __ctx_buff *ctx,
				     struct ipv4_ct_tuple *tuple,
				     struct ipv4_nat_entry *state,
				     __u32 l4_off, __u32 inner_l4_off)
{
	int ret;
	int flags = BPF_F_PSEUDO_HDR;
	struct csum_offset csum = {};
	__be32 sum;

	if (state->to_saddr == tuple->saddr &&
	    state->to_sport == tuple->sport)
		return 0;
	sum = csum_diff(&tuple->saddr, 4, &state->to_saddr, 4, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);

	if (state->to_sport != tuple->sport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, inner_l4_off,
					     offsetof(struct tcphdr, dest),
					     &csum, state->to_sport, tuple->sport);
			if (ret < 0)
				return ret;
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
		case IPPROTO_ICMP: {
			if (ctx_store_bytes(ctx, inner_l4_off +
						offsetof(struct icmphdr, un.echo.id),
						&state->to_sport,
						sizeof(state->to_sport), 0) < 0)
				return DROP_WRITE_ERROR;
			if (l4_csum_replace(ctx, inner_l4_off + offsetof(struct icmphdr, checksum),
					    tuple->sport,
					    state->to_sport,
					    sizeof(tuple->sport)) < 0)
				return DROP_CSUM_L4;
			break;
		}}
	}
	if (ctx_store_bytes(ctx, l4_off + sizeof(struct icmphdr) + offsetof(struct iphdr, daddr),
			    &state->to_saddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ipv4_csum_update_by_diff(ctx, l4_off + sizeof(struct icmphdr), sum) < 0)
		return DROP_CSUM_L3;
	if (csum.offset &&
	    csum_l4_replace(ctx, inner_l4_off, &csum, 0, sum, flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

static __always_inline bool
snat_v4_nat_can_skip(const struct ipv4_nat_target *target,
		     const struct ipv4_ct_tuple *tuple)
{
	__u16 sport = bpf_ntohs(tuple->sport);

#if defined(ENABLE_EGRESS_GATEWAY_COMMON) && defined(IS_BPF_HOST)
	if (target->egress_gateway)
		return false;
#endif

	return (!target->from_local_endpoint && sport < NAT_MIN_EGRESS);
}

static __always_inline bool
snat_v4_rev_nat_can_skip(const struct ipv4_nat_target *target, const struct ipv4_ct_tuple *tuple)
{
	__u16 dport = bpf_ntohs(tuple->dport);

	return dport < target->min_port || dport > target->max_port;
}

/* Expects to be called with a nodeport-level CT tuple (ie. CT_EGRESS):
 * - extracted from a request packet,
 * - on CT_NEW (ie. the tuple is reversed)
 */
static __always_inline __maybe_unused int
snat_v4_create_dsr(const struct ipv4_ct_tuple *tuple,
		   __be32 to_saddr, __be16 to_sport, __s8 *ext_err)
{
	struct ipv4_ct_tuple tmp = *tuple;
	struct ipv4_nat_entry state = {};
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	tmp.flags = TUPLE_F_OUT;
	tmp.sport = tuple->dport;
	tmp.dport = tuple->sport;

	state.common.created = bpf_mono_now();
	state.to_saddr = to_saddr;
	state.to_sport = to_sport;

	ret = map_update_elem(&SNAT_MAPPING_IPV4, &tmp, &state, 0);
	if (ret) {
		*ext_err = (__s8)ret;
		return DROP_NAT_NO_MAPPING;
	}

	return CTX_ACT_OK;
}

static __always_inline void snat_v4_init_tuple(const struct iphdr *ip4,
					       enum nat_dir dir,
					       struct ipv4_ct_tuple *tuple)
{
	tuple->nexthdr = ip4->protocol;
	tuple->daddr = ip4->daddr;
	tuple->saddr = ip4->saddr;
	tuple->flags = dir;
}

/* The function contains a core logic for deciding whether an egressing packet
 * has to be SNAT-ed, filling the relevant state in the target parameter if
 * that's the case.
 *
 * The function will set:
 * - target->addr to the SNAT IP address
 * - target->from_local_endpoint to true if the packet is sent from a local endpoint
 * - target->egress_gateway to true if the packet should be SNAT-ed because of
 *   an egress gateway policy
 *
 * On success, the function returns NAT_NEEDED if the packet should be SNAT-ed,
 * or NAT_PUNT_TO_STACK if it should not. On failure, it returns a negative
 * error code (distinct from NAT_PUNT_TO_STACK).
 */
static __always_inline int
snat_v4_needs_masquerade(struct __ctx_buff *ctx __maybe_unused,
			 struct ipv4_ct_tuple *tuple __maybe_unused,
			 int l4_off __maybe_unused,
			 struct ipv4_nat_target *target __maybe_unused)
{
	struct endpoint_info *local_ep __maybe_unused;
	struct remote_endpoint_info *remote_ep __maybe_unused;
	struct egress_gw_policy_entry *egress_gw_policy __maybe_unused;
	bool is_reply __maybe_unused = false;

#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
# if defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && defined(ENABLE_INTER_CLUSTER_SNAT)
	if (target->cluster_id != 0 &&
	    target->cluster_id != CLUSTER_ID) {
		target->addr = IPV4_INTER_CLUSTER_SNAT;
		target->from_local_endpoint = true;

		return NAT_NEEDED;
	}
# endif
#endif /* TUNNEL_MODE && IS_BPF_OVERLAY */

#if defined(ENABLE_MASQUERADE_IPV4) && defined(IS_BPF_HOST)
	if (tuple->saddr == IPV4_MASQUERADE) {
		target->addr = IPV4_MASQUERADE;
		target->needs_ct = true;

		return NAT_NEEDED;
	}

	local_ep = __lookup_ip4_endpoint(tuple->saddr);
	remote_ep = lookup_ip4_remote_endpoint(tuple->daddr, 0);

	/* Check if this packet belongs to reply traffic coming from a
	 * local endpoint.
	 *
	 * If local_ep is NULL, it means there's no endpoint running on the
	 * node which matches the packet source IP, which means we can
	 * skip the CT lookup since this cannot be reply traffic.
	 */
	if (local_ep) {
		int err;

		target->from_local_endpoint = true;

		err = ct_extract_ports4(ctx, l4_off, CT_EGRESS, tuple, NULL);
		if (err < 0)
			return err;

		is_reply = ct_is_reply4(get_ct_map4(tuple), tuple);

		/* SNAT code has its own port extraction logic: */
		tuple->dport = 0;
		tuple->sport = 0;
	}

/* Check if the packet matches an egress NAT policy and so needs to be SNAT'ed.
 *
 * This check must happen before the IPV4_SNAT_EXCLUSION_DST_CIDR check below as
 * the destination may be in the SNAT exclusion CIDR but regardless of that we
 * always want to SNAT a packet if it's matched by an egress NAT policy.
 */
#if defined(ENABLE_EGRESS_GATEWAY_COMMON)
	/* If the packet is destined to an entity inside the cluster, either EP
	 * or node, skip SNAT since only traffic leaving the cluster is supposed
	 * to be masqueraded with an egress IP.
	 */
	if (remote_ep &&
	    identity_is_cluster(remote_ep->sec_identity))
		goto skip_egress_gateway;

	/* If the packet is a reply it means that outside has initiated the
	 * connection, so no need to SNAT the reply.
	 */
	if (is_reply)
		goto skip_egress_gateway;

	if (egress_gw_snat_needed_hook(tuple->saddr, tuple->daddr, &target->addr)) {
		target->egress_gateway = true;
		/* If the endpoint is local, then the connection is already tracked. */
		if (!local_ep)
			target->needs_ct = true;

		return NAT_NEEDED;
	}
skip_egress_gateway:
#endif

#ifdef IPV4_SNAT_EXCLUSION_DST_CIDR
	/* Do not MASQ if a dst IP belongs to a pods CIDR
	 * (ipv4-native-routing-cidr if specified, otherwise local pod CIDR).
	 */
	if (ipv4_is_in_subnet(tuple->daddr, IPV4_SNAT_EXCLUSION_DST_CIDR,
			      IPV4_SNAT_EXCLUSION_DST_CIDR_LEN))
		return NAT_PUNT_TO_STACK;
#endif

	/* if this is a localhost endpoint, no SNAT is needed */
	if (local_ep && (local_ep->flags & ENDPOINT_F_HOST))
		return NAT_PUNT_TO_STACK;

	if (remote_ep) {
#ifdef ENABLE_IP_MASQ_AGENT_IPV4
		/* Do not SNAT if dst belongs to any ip-masq-agent
		 * subnet.
		 */
		struct lpm_v4_key pfx;

		pfx.lpm.prefixlen = 32;
		memcpy(pfx.lpm.data, &tuple->daddr, sizeof(pfx.addr));
		if (map_lookup_elem(&IP_MASQ_AGENT_IPV4, &pfx))
			return NAT_PUNT_TO_STACK;
#endif
#ifndef TUNNEL_MODE
		/* In the tunnel mode, a packet from a local ep
		 * to a remote node is not encap'd, and is sent
		 * via a native dev. Therefore, such packet has
		 * to be MASQ'd. Otherwise, it might be dropped
		 * either by underlying network (e.g. AWS drops
		 * packets by default from unknown subnets) or
		 * by the remote node if its native dev's
		 * rp_filter=1.
		 */
		if (identity_is_remote_node(remote_ep->sec_identity))
			return NAT_PUNT_TO_STACK;
#endif

		/* If the packet is a reply it means that outside has
		 * initiated the connection, so no need to SNAT the
		 * reply.
		 */
		if (!is_reply && local_ep) {
			target->addr = IPV4_MASQUERADE;
			return NAT_NEEDED;
		}
	}
#endif /*ENABLE_MASQUERADE_IPV4 && IS_BPF_HOST */

	return NAT_PUNT_TO_STACK;
}

static __always_inline __maybe_unused int
snat_v4_nat_handle_icmp_frag_needed(struct __ctx_buff *ctx, __u64 off,
				    bool has_l4_header)
{
	struct ipv4_ct_tuple tuple = {};
	struct ipv4_nat_entry *state;
	struct iphdr iphdr;
	__u32 icmpoff = off + sizeof(struct icmphdr);
	__be16 identifier;
	__u8 type;
	int ret;

	/* According to the RFC 5508, any networking equipment that is
	 * responding with an ICMP Error packet should embed the original
	 * packet in its response.
	 */
	if (ctx_load_bytes(ctx, icmpoff, &iphdr,
			   sizeof(iphdr)) < 0)
		return DROP_INVALID;
	/* From the embedded IP headers we should be able to determine
	 * corresponding protocol, IP src/dst of the packet sent to resolve
	 * the NAT session.
	 */
	tuple.nexthdr = iphdr.protocol;
	tuple.saddr = iphdr.daddr;
	tuple.daddr = iphdr.saddr;
	tuple.flags = NAT_DIR_EGRESS;

	icmpoff += ipv4_hdrlen(&iphdr);
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif /* ENABLE_SCTP */
		/* No reasons to handle IP fragmentation for this case as it is
		 * expected that DF isn't set for this particular context.
		 */
		if (l4_load_ports(ctx, icmpoff, &tuple.dport) < 0)
			return DROP_INVALID;
		break;
	case IPPROTO_ICMP:
		/* No reasons to see a packet different than ICMP_ECHOREPLY. */
		if (ctx_load_bytes(ctx, icmpoff, &type,
				   sizeof(type)) < 0 ||
		    type != ICMP_ECHOREPLY)
			return DROP_INVALID;
		if (ctx_load_bytes(ctx, icmpoff +
			    offsetof(struct icmphdr, un.echo.id),
			&identifier, sizeof(identifier)) < 0)
			return DROP_INVALID;
		tuple.sport = identifier;
		tuple.dport = 0;
		break;
	default:
		return DROP_UNKNOWN_L4;
	}
	state = snat_v4_lookup(&tuple);
	if (!state)
		return NAT_PUNT_TO_STACK;

	/* We found SNAT entry to NAT embedded packet. The destination addr
	 * should be NATed according to the entry.
	 */
	ret = snat_v4_icmp_rewrite_egress_embedded(ctx, &tuple, state,
						   off, icmpoff);
	if (IS_ERR(ret))
		return ret;

	/* Rewrite outer headers for ICMP_FRAG_NEEDED. No port rewrite needed. */
	return snat_v4_rewrite_headers(ctx, IPPROTO_ICMP, ETH_HLEN, has_l4_header, off,
				       tuple.saddr, state->to_saddr, IPV4_SADDR_OFF,
				       0, 0, 0);
}

static __always_inline int
__snat_v4_nat(struct __ctx_buff *ctx, struct ipv4_ct_tuple *tuple,
	      struct iphdr *ip4, bool has_l4_header, int l4_off,
	      bool update_tuple, const struct ipv4_nat_target *target,
	      __u16 port_off, struct trace_ctx *trace, __s8 *ext_err)
{
	struct ipv4_nat_entry *state, tmp;
	int ret;

	ret = snat_v4_nat_handle_mapping(ctx, tuple, has_l4_header, &state,
					 &tmp, ip4, l4_off, target, trace, ext_err);
	if (ret < 0)
		return ret;

	ret = snat_v4_rewrite_headers(ctx, tuple->nexthdr, ETH_HLEN, has_l4_header, l4_off,
				      tuple->saddr, state->to_saddr, IPV4_SADDR_OFF,
				      tuple->sport, state->to_sport, port_off);

	if (update_tuple) {
		tuple->saddr = state->to_saddr;
		tuple->sport = state->to_sport;
	}

	return ret;
}

static __always_inline __maybe_unused int
snat_v4_nat(struct __ctx_buff *ctx, struct ipv4_ct_tuple *tuple,
	    struct iphdr *ip4, int off, bool has_l4_header,
	    const struct ipv4_nat_target *target,
	    struct trace_ctx *trace, __s8 *ext_err)
{
	struct icmphdr icmphdr __align_stack_8;
	__u16 port_off;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	switch (tuple->nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (ipv4_load_l4_ports(ctx, NULL, off, CT_EGRESS,
				       &tuple->dport, &has_l4_header) < 0)
			return DROP_INVALID;

		ipv4_ct_tuple_swap_ports(tuple);
		port_off = TCP_SPORT_OFF;
		break;
	case IPPROTO_ICMP:
		if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;

		switch (icmphdr.type) {
		case ICMP_ECHO:
			tuple->dport = 0;
			tuple->sport = icmphdr.un.echo.id;
			port_off = offsetof(struct icmphdr, un.echo.id);
			break;
		case ICMP_ECHOREPLY:
			return NAT_PUNT_TO_STACK;
		case ICMP_DEST_UNREACH:
			if (icmphdr.code != ICMP_FRAG_NEEDED)
				return DROP_UNKNOWN_ICMP_CODE;
			return snat_v4_nat_handle_icmp_frag_needed(ctx, off, has_l4_header);
		default:
			return DROP_NAT_UNSUPP_PROTO;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v4_nat_can_skip(target, tuple))
		return NAT_PUNT_TO_STACK;

	return __snat_v4_nat(ctx, tuple, ip4, has_l4_header, off, false, target,
			     port_off, trace, ext_err);
}

static __always_inline __maybe_unused int
snat_v4_rev_nat_handle_icmp_frag_needed(struct __ctx_buff *ctx,
					__u64 inner_l3_off,
					struct ipv4_nat_entry **state)
{
	struct ipv4_ct_tuple tuple = {};
	struct iphdr iphdr;
	__be16 identifier;
	__u16 port_off;
	__u32 icmpoff;
	__u8 type;

	/* According to the RFC 5508, any networking equipment that is
	 * responding with an ICMP Error packet should embed the original
	 * packet in its response.
	 */

	if (ctx_load_bytes(ctx, inner_l3_off, &iphdr, sizeof(iphdr)) < 0)
		return DROP_INVALID;

	/* From the embedded IP headers we should be able to determine
	 * corresponding protocol, IP src/dst of the packet sent to resolve the
	 * NAT session.
	 */
	tuple.nexthdr = iphdr.protocol;
	tuple.saddr = iphdr.daddr;
	tuple.daddr = iphdr.saddr;
	tuple.flags = NAT_DIR_INGRESS;

	icmpoff = inner_l3_off + ipv4_hdrlen(&iphdr);
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		/* No reasons to handle IP fragmentation for this case as it is
		 * expected that DF isn't set for this particular context.
		 */
		if (l4_load_ports(ctx, icmpoff, &tuple.dport) < 0)
			return DROP_INVALID;

		port_off = TCP_SPORT_OFF;
		break;
	case IPPROTO_ICMP:
		/* No reasons to see a packet different than ICMP_ECHO. */
		if (ctx_load_bytes(ctx, icmpoff, &type, sizeof(type)) < 0 ||
		    type != ICMP_ECHO)
			return DROP_INVALID;

		port_off = offsetof(struct icmphdr, un.echo.id);

		if (ctx_load_bytes(ctx, icmpoff + port_off,
				   &identifier, sizeof(identifier)) < 0)
			return DROP_INVALID;
		tuple.sport = 0;
		tuple.dport = identifier;
		break;
	default:
		return NAT_PUNT_TO_STACK;
	}

	*state = snat_v4_lookup(&tuple);
	if (!*state)
		return NAT_PUNT_TO_STACK;

	/* The embedded packet was SNATed on egress. Reverse it again: */
	return snat_v4_rewrite_headers(ctx, tuple.nexthdr, inner_l3_off, true, icmpoff,
				       tuple.daddr, (*state)->to_daddr, IPV4_SADDR_OFF,
				       tuple.dport, (*state)->to_dport, port_off);
}

static __always_inline __maybe_unused int
snat_v4_rev_nat(struct __ctx_buff *ctx, const struct ipv4_nat_target *target,
		struct trace_ctx *trace, __s8 *ext_err __maybe_unused)
{
	struct icmphdr icmphdr __align_stack_8;
	struct ipv4_nat_entry *state = NULL;
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	bool has_l4_header = true;
	__u64 off, inner_l3_off;
	__be16 to_dport = 0;
	__u16 port_off = 0;
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	snat_v4_init_tuple(ip4, NAT_DIR_INGRESS, &tuple);

	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (ipv4_load_l4_ports(ctx, ip4, off, CT_INGRESS,
				       &tuple.dport, &has_l4_header) < 0)
			return DROP_INVALID;
		ipv4_ct_tuple_swap_ports(&tuple);
		port_off = TCP_DPORT_OFF;
		break;
	case IPPROTO_ICMP:
		if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;
		switch (icmphdr.type) {
		case ICMP_ECHOREPLY:
			tuple.dport = icmphdr.un.echo.id;
			tuple.sport = 0;
			port_off = offsetof(struct icmphdr, un.echo.id);
			break;
		case ICMP_DEST_UNREACH:
			if (icmphdr.code != ICMP_FRAG_NEEDED)
				return NAT_PUNT_TO_STACK;

			inner_l3_off = off + sizeof(struct icmphdr);

			ret = snat_v4_rev_nat_handle_icmp_frag_needed(ctx,
								      inner_l3_off,
								      &state);
			if (IS_ERR(ret))
				return ret;

			has_l4_header = true;
			goto rewrite;
		default:
			return NAT_PUNT_TO_STACK;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v4_rev_nat_can_skip(target, &tuple))
		return NAT_PUNT_TO_STACK;
	ret = snat_v4_rev_nat_handle_mapping(ctx, &tuple, has_l4_header, &state,
					     ip4, off, target, trace);
	if (ret < 0)
		return ret;

	/* Skip port rewrite for ICMP_DEST_UNREACH by passing old_port == new_port == 0. */
	to_dport = state->to_dport;

rewrite:
	return snat_v4_rewrite_headers(ctx, tuple.nexthdr, ETH_HLEN, has_l4_header, off,
				       tuple.daddr, state->to_daddr, IPV4_DADDR_OFF,
				       tuple.dport, to_dport, port_off);
}
#else
static __always_inline __maybe_unused
int snat_v4_nat(struct __ctx_buff *ctx __maybe_unused,
		const struct ipv4_nat_target *target __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline __maybe_unused
int snat_v4_rev_nat(struct __ctx_buff *ctx __maybe_unused,
		    const struct ipv4_nat_target *target __maybe_unused)
{
	return CTX_ACT_OK;
}
#endif

struct ipv6_nat_entry {
	struct nat_entry common;
	union {
		struct lb6_reverse_nat nat_info;
		struct {
			union v6addr to_saddr;
			__be16       to_sport;
		};
		struct {
			union v6addr to_daddr;
			__be16       to_dport;
		};
	};
};

struct ipv6_nat_target {
	union v6addr addr;
	const __u16 min_port; /* host endianness */
	const __u16 max_port; /* host endianness */
	bool from_local_endpoint;
	bool needs_ct;
};

#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_ct_tuple);
	__type(value, struct ipv6_nat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SNAT_MAPPING_IPV6_SIZE);
} SNAT_MAPPING_IPV6 __section_maps_btf;

#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 256);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_LRU_HASH);
		__type(key, struct ipv6_ct_tuple);
		__type(value, struct ipv6_nat_entry);
		__uint(max_entries, SNAT_MAPPING_IPV6_SIZE);
	});
} PER_CLUSTER_SNAT_MAPPING_IPV6 __section_maps_btf;
#endif

#ifdef ENABLE_IP_MASQ_AGENT_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v6_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} IP_MASQ_AGENT_IPV6 __section_maps_btf;
#endif

static __always_inline void *
get_cluster_snat_map_v6(__u32 cluster_id __maybe_unused)
{
#if defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && defined(ENABLE_INTER_CLUSTER_SNAT)
	if (cluster_id != 0 && cluster_id != CLUSTER_ID)
		return map_lookup_elem(&PER_CLUSTER_SNAT_MAPPING_IPV6, &cluster_id);
#endif
	return &SNAT_MAPPING_IPV6;
}

static __always_inline
struct ipv6_nat_entry *snat_v6_lookup(const struct ipv6_ct_tuple *tuple)
{
	return __snat_lookup(&SNAT_MAPPING_IPV6, tuple);
}

static __always_inline int snat_v6_update(struct ipv6_ct_tuple *otuple,
					  struct ipv6_nat_entry *ostate,
					  struct ipv6_ct_tuple *rtuple,
					  struct ipv6_nat_entry *rstate)
{
	return __snat_update(&SNAT_MAPPING_IPV6, otuple, ostate,
			     rtuple, rstate);
}

static __always_inline int snat_v6_new_mapping(struct __ctx_buff *ctx,
					       struct ipv6_ct_tuple *otuple,
					       struct ipv6_nat_entry *ostate,
					       const struct ipv6_nat_target *target,
					       bool needs_ct, __s8 *ext_err)
{
	struct ipv6_ct_tuple rtuple = {};
	struct ipv6_nat_entry rstate;
	int ret, retries;
	__u16 port;

	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;
	/* .to_sport is selected below */

	rtuple.flags = TUPLE_F_IN;
	rtuple.nexthdr = otuple->nexthdr;
	rtuple.saddr = otuple->daddr;
	rtuple.daddr = ostate->to_saddr;
	rtuple.sport = otuple->dport;
	/* .dport is selected below */

	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	ostate->common.needs_ct = needs_ct;
	rstate.common.needs_ct = needs_ct;

#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		rtuple.dport = bpf_htons(port);

		if (!snat_v6_lookup(&rtuple))
			goto create_nat_entries;

		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
	}

	ret = DROP_NAT_NO_MAPPING;
	goto out;

create_nat_entries:
	ostate->to_sport = rtuple.dport;
	ostate->common.created = bpf_mono_now();
	rstate.common.created = ostate->common.created;

	ret = snat_v6_update(otuple, ostate, &rtuple, &rstate);
	if (ret < 0) {
		if (ext_err)
			*ext_err = (__s8)ret;
		ret = DROP_NAT_NO_MAPPING;
	}

out:
	if (retries > SNAT_SIGNAL_THRES)
		send_signal_nat_fill_up(ctx, SIGNAL_PROTO_V6);

	return ret;
}

static __always_inline int
snat_v6_nat_handle_mapping(struct __ctx_buff *ctx,
			   struct ipv6_ct_tuple *tuple,
			   struct ipv6_nat_entry **state,
			   struct ipv6_nat_entry *tmp,
			   __u32 off,
			   const struct ipv6_nat_target *target,
			   struct trace_ctx *trace,
			   __s8 *ext_err)
{
	bool needs_ct = target->needs_ct;

	*state = snat_v6_lookup(tuple);

	if (needs_ct) {
		struct ipv6_ct_tuple tuple_snat;
		struct ct_state ct_state = {};
		int ret;

		memcpy(&tuple_snat, tuple, sizeof(tuple_snat));
		/* Lookup with SCOPE_FORWARD. Ports are already in correct layout: */
		ipv6_ct_tuple_swap_addrs(&tuple_snat);

		ret = ct_lazy_lookup6(get_ct_map6(&tuple_snat), &tuple_snat,
				      ctx, off, CT_EGRESS, SCOPE_FORWARD,
				      CT_ENTRY_ANY, &ct_state, &trace->monitor);
		if (ret < 0)
			return ret;

		trace->reason = (enum trace_reason)ret;
		if (ret == CT_NEW) {
			ret = ct_create6(get_ct_map6(&tuple_snat), NULL,
					 &tuple_snat, ctx, CT_EGRESS,
					 &ct_state, false, false, ext_err);
			if (IS_ERR(ret))
				return ret;
		}
	}

	if (*state)
		return 0;
	else
		return snat_v6_new_mapping(ctx, tuple, (*state = tmp), target, needs_ct,
					   ext_err);
}

static __always_inline int
snat_v6_rev_nat_handle_mapping(struct __ctx_buff *ctx,
			       struct ipv6_ct_tuple *tuple,
			       struct ipv6_nat_entry **state,
			       __u32 off,
			       struct trace_ctx *trace)
{
	*state = snat_v6_lookup(tuple);

	if (*state && (*state)->common.needs_ct) {
		struct ipv6_ct_tuple tuple_revsnat;
		struct ct_state ct_state = {};
		int ret;

		memcpy(&tuple_revsnat, tuple, sizeof(tuple_revsnat));
		ipv6_addr_copy(&tuple_revsnat.daddr, &(*state)->to_daddr);
		tuple_revsnat.dport = (*state)->to_dport;

		/* CT expects a tuple with the source and destination ports reversed,
		 * while NAT uses normal tuples that match packet headers.
		 */
		ipv6_ct_tuple_swap_ports(&tuple_revsnat);

		ret = ct_lazy_lookup6(get_ct_map6(&tuple_revsnat), &tuple_revsnat,
				      ctx, off, CT_INGRESS, SCOPE_REVERSE,
				      CT_ENTRY_ANY, &ct_state, &trace->monitor);
		if (ret < 0)
			return ret;

		trace->reason = (enum trace_reason)ret;
	}

	if (*state)
		return 0;

	return DROP_NAT_NO_MAPPING;
}

static __always_inline int
snat_v6_rewrite_headers(struct __ctx_buff *ctx, __u8 nexthdr, int l3_off, int l4_off,
			union v6addr *old_addr, union v6addr *new_addr, __u16 addr_off,
			__be16 old_port, __be16 new_port, __u16 port_off)
{
	struct csum_offset csum = {};
	__wsum sum;

	/* No change needed: */
	if (ipv6_addr_equals(old_addr, new_addr) && old_port == new_port)
		return 0;

	sum = csum_diff(old_addr, 16, new_addr, 16, 0);
	if (ctx_store_bytes(ctx, l3_off + addr_off, new_addr, 16, 0) < 0)
		return DROP_WRITE_ERROR;

	csum_l4_offset_and_flags(nexthdr, &csum);

	if (old_port != new_port) {
		__be32 from = old_port;
		__be32 to = new_port;

		switch (nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_ICMPV6:
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
		default:
			return DROP_UNKNOWN_L4;
		}

		sum = csum_diff(&from, 4, &to, 4, sum);
		if (l4_store_port(ctx, l4_off, port_off, new_port) < 0)
			return DROP_WRITE_ERROR;
	}

	if (csum.offset &&
	    csum_l4_replace(ctx, l4_off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}

static __always_inline int snat_v6_rewrite_ingress(struct __ctx_buff *ctx,
						   struct ipv6_ct_tuple *tuple,
						   struct ipv6_nat_entry *state,
						   __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum;
	int ret;

	if (ipv6_addr_equals(&state->to_daddr, &tuple->daddr) &&
	    state->to_dport == tuple->dport)
		return 0;
	sum = csum_diff(&tuple->daddr, 16, &state->to_daddr, 16, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_dport != tuple->dport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, off,
					     offsetof(struct tcphdr, dest),
					     &csum, state->to_dport,
					     tuple->dport);
			if (ret < 0)
				return ret;
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
		case IPPROTO_ICMPV6: {
			__u8 type = 0;
			__be32 from, to;

			if (icmp6_load_type(ctx, off, &type) < 0)
				return DROP_INVALID;
			if (type == ICMPV6_ECHO_REPLY) {
				if (ctx_store_bytes(ctx, off +
						    offsetof(struct icmp6hdr,
							     icmp6_dataun.u_echo.identifier),
						    &state->to_dport,
						    sizeof(state->to_dport), 0) < 0)
					return DROP_WRITE_ERROR;
				from = tuple->dport;
				to = state->to_dport;
				sum = csum_diff(&from, 4, &to, 4, sum);
			}
			break;
		}}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			    &state->to_daddr, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;
	return 0;
}

static __always_inline bool
snat_v6_nat_can_skip(const struct ipv6_nat_target *target,
		     const struct ipv6_ct_tuple *tuple)
{
	__u16 sport = bpf_ntohs(tuple->sport);

	return (!target->from_local_endpoint && sport < NAT_MIN_EGRESS);
}

static __always_inline bool
snat_v6_rev_nat_can_skip(const struct ipv6_nat_target *target, const struct ipv6_ct_tuple *tuple)
{
	__u16 dport = bpf_ntohs(tuple->dport);

	return dport < target->min_port || dport > target->max_port;
}

static __always_inline __maybe_unused int
snat_v6_create_dsr(const struct ipv6_ct_tuple *tuple, union v6addr *to_saddr,
		   __be16 to_sport, __s8 *ext_err)
{
	struct ipv6_ct_tuple tmp = *tuple;
	struct ipv6_nat_entry state = {};
	int ret;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	tmp.flags = TUPLE_F_OUT;
	tmp.sport = tuple->dport;
	tmp.dport = tuple->sport;

	state.common.created = bpf_mono_now();
	ipv6_addr_copy(&state.to_saddr, to_saddr);
	state.to_sport = to_sport;

	ret = map_update_elem(&SNAT_MAPPING_IPV6, &tmp, &state, 0);
	if (ret) {
		*ext_err = (__s8)ret;
		return DROP_NAT_NO_MAPPING;
	}

	return CTX_ACT_OK;
}

static __always_inline void snat_v6_init_tuple(const struct ipv6hdr *ip6,
					       enum nat_dir dir,
					       struct ipv6_ct_tuple *tuple)
{
	ipv6_addr_copy(&tuple->daddr, (union v6addr *)&ip6->daddr);
	ipv6_addr_copy(&tuple->saddr, (union v6addr *)&ip6->saddr);
	tuple->flags = dir;
}

static __always_inline int
snat_v6_needs_masquerade(struct __ctx_buff *ctx __maybe_unused,
			 struct ipv6_ct_tuple *tuple __maybe_unused,
			 int l4_off __maybe_unused,
			 struct ipv6_nat_target *target __maybe_unused)
{
	union v6addr masq_addr __maybe_unused;
	struct remote_endpoint_info *remote_ep __maybe_unused;
	struct endpoint_info *local_ep __maybe_unused;
	bool is_reply __maybe_unused = false;

	/* See comments in snat_v4_needs_masquerade(). */
#if defined(ENABLE_MASQUERADE_IPV6) && defined(IS_BPF_HOST)
	BPF_V6(masq_addr, IPV6_MASQUERADE);
	if (ipv6_addr_equals(&tuple->saddr, &masq_addr)) {
		ipv6_addr_copy(&target->addr, &masq_addr);
		target->needs_ct = true;

		return NAT_NEEDED;
	}

	local_ep = __lookup_ip6_endpoint(&tuple->saddr);
	remote_ep = lookup_ip6_remote_endpoint(&tuple->daddr, 0);

	if (local_ep) {
		int err;

		target->from_local_endpoint = true;

		err = ct_extract_ports6(ctx, l4_off, tuple);
		if (err < 0)
			return err;

		is_reply = ct_is_reply6(get_ct_map6(tuple), tuple);

		/* SNAT code has its own port extraction logic: */
		tuple->dport = 0;
		tuple->sport = 0;
	}

# ifdef IPV6_SNAT_EXCLUSION_DST_CIDR
	{
		union v6addr excl_cidr_mask = IPV6_SNAT_EXCLUSION_DST_CIDR_MASK;
		union v6addr excl_cidr = IPV6_SNAT_EXCLUSION_DST_CIDR;

		if (ipv6_addr_in_net(&tuple->daddr, &excl_cidr, &excl_cidr_mask))
			return NAT_PUNT_TO_STACK;
	}
# endif /* IPV6_SNAT_EXCLUSION_DST_CIDR */

	/* if this is a localhost endpoint, no SNAT is needed */
	if (local_ep && (local_ep->flags & ENDPOINT_F_HOST))
		return NAT_PUNT_TO_STACK;

	if (remote_ep) {
#ifdef ENABLE_IP_MASQ_AGENT_IPV6
		/* Do not SNAT if dst belongs to any ip-masq-agent subnet. */
		struct lpm_v6_key pfx __align_stack_8;

		pfx.lpm.prefixlen = sizeof(pfx.addr) * 8;
		/* pfx.lpm is aligned on 8 bytes on the stack, but pfx.lpm.data
		 * is on 4 (after pfx.lpm.prefixlen). As the CT tuple is on the
		 * stack as well, we need to copy piece-by-piece.
		 */
		memcpy(pfx.lpm.data, &tuple->daddr.p1, 4);
		memcpy(pfx.lpm.data + 4, &tuple->daddr.p2, 4);
		memcpy(pfx.lpm.data + 8, &tuple->daddr.p3, 4);
		memcpy(pfx.lpm.data + 12, &tuple->daddr.p4, 4);
		if (map_lookup_elem(&IP_MASQ_AGENT_IPV6, &pfx))
			return NAT_PUNT_TO_STACK;
#endif

# ifndef TUNNEL_MODE
		if (identity_is_remote_node(remote_ep->sec_identity))
			return NAT_PUNT_TO_STACK;
# endif /* TUNNEL_MODE */

		if (!is_reply && local_ep) {
			ipv6_addr_copy(&target->addr, &masq_addr);
			return NAT_NEEDED;
		}
	}
#endif /* ENABLE_MASQUERADE_IPV6 && IS_BPF_HOST */

	return NAT_PUNT_TO_STACK;
}

static __always_inline int
__snat_v6_nat(struct __ctx_buff *ctx, struct ipv6_ct_tuple *tuple,
	      int l4_off, bool update_tuple,
	      const struct ipv6_nat_target *target, __u16 port_off,
	      struct trace_ctx *trace, __s8 *ext_err)
{
	struct ipv6_nat_entry *state, tmp;
	int ret;

	ret = snat_v6_nat_handle_mapping(ctx, tuple, &state, &tmp, l4_off,
					 target, trace, ext_err);
	if (ret < 0)
		return ret;

	ret = snat_v6_rewrite_headers(ctx, tuple->nexthdr, ETH_HLEN, l4_off,
				      &tuple->saddr, &state->to_saddr, IPV6_SADDR_OFF,
				      tuple->sport, state->to_sport, port_off);

	if (update_tuple) {
		ipv6_addr_copy(&tuple->saddr, &state->to_saddr);
		tuple->sport = state->to_sport;
	}

	return ret;
}

static __always_inline __maybe_unused int
snat_v6_nat(struct __ctx_buff *ctx, struct ipv6_ct_tuple *tuple, int off,
	    const struct ipv6_nat_target *target, struct trace_ctx *trace,
	    __s8 *ext_err)
{
	struct icmp6hdr icmp6hdr __align_stack_8;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u16 port_off;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	switch (tuple->nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;

		tuple->dport = l4hdr.dport;
		tuple->sport = l4hdr.sport;
		port_off = TCP_SPORT_OFF;
		break;
	case IPPROTO_ICMPV6:
		if (ctx_load_bytes(ctx, off, &icmp6hdr, sizeof(icmp6hdr)) < 0)
			return DROP_INVALID;

		switch (icmp6hdr.icmp6_type) {
		case ICMPV6_ECHO_REPLY:
		case ICMP6_NS_MSG_TYPE:
		case ICMP6_NA_MSG_TYPE:
			return NAT_PUNT_TO_STACK;
		case ICMPV6_ECHO_REQUEST:
			tuple->dport = 0;
			tuple->sport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			port_off = offsetof(struct icmp6hdr,
					    icmp6_dataun.u_echo.identifier);
			break;
		default:
			return DROP_NAT_UNSUPP_PROTO;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v6_nat_can_skip(target, tuple))
		return NAT_PUNT_TO_STACK;

	return __snat_v6_nat(ctx, tuple, off, false, target, port_off,
			     trace, ext_err);
}

static __always_inline __maybe_unused int
snat_v6_rev_nat_handle_icmp_pkt_toobig(struct __ctx_buff *ctx,
				       __u32 inner_l3_off,
				       struct ipv6_nat_entry **state)
{
	struct ipv6_ct_tuple tuple = {};
	struct ipv6hdr iphdr;
	__be16 identifier;
	__u16 port_off;
	__u32 icmpoff;
	__u8 type;
	int hdrlen;

	/* According to the RFC 5508, any networking
	 * equipment that is responding with an ICMP Error
	 * packet should embed the original packet in its
	 * response.
	 */

	if (ctx_load_bytes(ctx, inner_l3_off, &iphdr, sizeof(iphdr)) < 0)
		return DROP_INVALID;

	/* From the embedded IP headers we should be able
	 * to determine corresponding protocol, IP src/dst
	 * of the packet sent to resolve the NAT session.
	 */

	tuple.nexthdr = iphdr.nexthdr;
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&iphdr.daddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&iphdr.saddr);
	tuple.flags = NAT_DIR_INGRESS;

	hdrlen = ipv6_hdrlen_offset(ctx, &tuple.nexthdr, inner_l3_off);
	if (hdrlen < 0)
		return hdrlen;

	icmpoff = inner_l3_off + hdrlen;

	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		/* No reasons to handle IP fragmentation for this case
		 * as it is expected that DF isn't set for this particular
		 * context.
		 */
		if (l4_load_ports(ctx, icmpoff, &tuple.dport) < 0)
			return DROP_INVALID;

		port_off = TCP_SPORT_OFF;
		break;
	case IPPROTO_ICMPV6:
		/* No reasons to see a packet different than
		 * ICMPV6_ECHO_REQUEST.
		 */
		if (icmp6_load_type(ctx, icmpoff, &type) < 0 ||
		    type != ICMPV6_ECHO_REQUEST)
			return DROP_INVALID;

		port_off = offsetof(struct icmp6hdr,
				    icmp6_dataun.u_echo.identifier);

		if (ctx_load_bytes(ctx, icmpoff + port_off,
				   &identifier, sizeof(identifier)) < 0)
			return DROP_INVALID;
		tuple.sport = 0;
		tuple.dport = identifier;
		break;
	default:
		return NAT_PUNT_TO_STACK;
	}

	*state = snat_v6_lookup(&tuple);
	if (!*state)
		return NAT_PUNT_TO_STACK;

	/* The embedded packet was SNATed on egress. Reverse it again: */
	return snat_v6_rewrite_headers(ctx, tuple.nexthdr, inner_l3_off, icmpoff,
				       &tuple.daddr, &(*state)->to_daddr, IPV6_SADDR_OFF,
				       tuple.dport, (*state)->to_dport, port_off);
}

static __always_inline __maybe_unused int
snat_v6_rev_nat(struct __ctx_buff *ctx, const struct ipv6_nat_target *target,
		struct trace_ctx *trace, __s8 *ext_err __maybe_unused)
{
	struct icmp6hdr icmp6hdr __align_stack_8;
	struct ipv6_nat_entry *state = NULL;
	struct ipv6_ct_tuple tuple = {};
	__u32 off, inner_l3_off;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, hdrlen;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	snat_v6_init_tuple(ip6, NAT_DIR_INGRESS, &tuple);

	off = ((void *)ip6 - data) + hdrlen;
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		break;
	case IPPROTO_ICMPV6:
		if (ctx_load_bytes(ctx, off, &icmp6hdr, sizeof(icmp6hdr)) < 0)
			return DROP_INVALID;
		switch (icmp6hdr.icmp6_type) {
		case ICMPV6_ECHO_REPLY:
			tuple.dport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			tuple.sport = 0;
			break;
		case ICMPV6_PKT_TOOBIG:
			/* ICMPV6_PKT_TOOBIG does not include identifer and
			 * sequence in its headers.
			 */
			inner_l3_off = off + sizeof(struct icmp6hdr) -
				       field_sizeof(struct icmp6hdr, icmp6_dataun.u_echo);

			ret = snat_v6_rev_nat_handle_icmp_pkt_toobig(ctx,
								     inner_l3_off,
								     &state);
			if (IS_ERR(ret))
				return ret;

			goto rewrite;
		default:
			return NAT_PUNT_TO_STACK;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v6_rev_nat_can_skip(target, &tuple))
		return NAT_PUNT_TO_STACK;
	ret = snat_v6_rev_nat_handle_mapping(ctx, &tuple, &state, off, trace);
	if (ret < 0)
		return ret;

rewrite:
	return snat_v6_rewrite_ingress(ctx, &tuple, state, off);
}
#else
static __always_inline __maybe_unused
int snat_v6_nat(struct __ctx_buff *ctx __maybe_unused,
		const struct ipv6_nat_target *target __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline __maybe_unused
int snat_v6_rev_nat(struct __ctx_buff *ctx __maybe_unused,
		    const struct ipv6_nat_target *target __maybe_unused)
{
	return CTX_ACT_OK;
}
#endif

#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)
static __always_inline int
snat_remap_rfc8215(struct __ctx_buff *ctx, const struct iphdr *ip4, int l3_off)
{
	union v6addr src6, dst6;

	build_v4_in_v6_rfc8215(&src6, ip4->saddr);
	build_v4_in_v6(&dst6, ip4->daddr);
	return ipv4_to_ipv6(ctx, l3_off, &src6, &dst6);
}

static __always_inline bool
__snat_v6_has_v4_complete(struct ipv6_ct_tuple *tuple6,
			  const struct ipv4_ct_tuple *tuple4)
{
	build_v4_in_v6(&tuple6->daddr, tuple4->daddr);
	tuple6->nexthdr = tuple4->nexthdr;
	/* tuple4 has ports in swapped order: */
	tuple6->sport = tuple4->dport;
	tuple6->dport = tuple4->sport;
	tuple6->flags = NAT_DIR_INGRESS;
	return snat_v6_lookup(tuple6);
}

static __always_inline bool
snat_v6_has_v4_match_rfc8215(const struct ipv4_ct_tuple *tuple4)
{
	struct ipv6_ct_tuple tuple6;

	memset(&tuple6, 0, sizeof(tuple6));
	build_v4_in_v6_rfc8215(&tuple6.saddr, tuple4->saddr);
	return __snat_v6_has_v4_complete(&tuple6, tuple4);
}

static __always_inline bool
snat_v6_has_v4_match(const struct ipv4_ct_tuple *tuple4)
{
	struct ipv6_ct_tuple tuple6;

	memset(&tuple6, 0, sizeof(tuple6));
	build_v4_in_v6(&tuple6.saddr, tuple4->saddr);
	return __snat_v6_has_v4_complete(&tuple6, tuple4);
}
#else
static __always_inline bool
snat_v6_has_v4_match(const struct ipv4_ct_tuple *tuple4 __maybe_unused)
{
	return false;
}
#endif /* ENABLE_IPV6 && ENABLE_NODEPORT */

#endif /* __LIB_NAT__ */
