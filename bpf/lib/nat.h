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
#include "egress_policies.h"
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

#define NAT_CONTINUE_XLATE	0

#ifdef HAVE_LARGE_INSN_LIMIT
# define SNAT_COLLISION_RETRIES		128
# define SNAT_SIGNAL_THRES		64
#else
# define SNAT_COLLISION_RETRIES		32
# define SNAT_SIGNAL_THRES		16
#endif

static __always_inline __be16 __snat_clamp_port_range(__u16 start, __u16 end,
						      __u16 val)
{
	return (val % (__u16)(end - start)) + start;
}

static __always_inline __maybe_unused __be16
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
	bool src_from_world;
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

static __always_inline int snat_v4_update(const struct ipv4_ct_tuple *otuple,
					  const struct ipv4_nat_entry *ostate,
					  const struct ipv4_ct_tuple *rtuple,
					  const struct ipv4_nat_entry *rstate)
{
	return __snat_update(&SNAT_MAPPING_IPV4, otuple, ostate,
			     rtuple, rstate);
}

static __always_inline void snat_v4_swap_tuple(const struct ipv4_ct_tuple *otuple,
					       struct ipv4_ct_tuple *rtuple)
{
	memset(rtuple, 0, sizeof(*rtuple));
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->daddr = otuple->saddr;
	rtuple->saddr = otuple->daddr;
	rtuple->dport = otuple->sport;
	rtuple->sport = otuple->dport;
	rtuple->flags = otuple->flags == NAT_DIR_EGRESS ?
			NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

static __always_inline int snat_v4_new_mapping(struct __ctx_buff *ctx,
					       struct ipv4_ct_tuple *otuple,
					       struct ipv4_nat_entry *ostate,
					       const struct ipv4_nat_target *target,
					       bool needs_ct, __s8 *ext_err)
{
	int ret = DROP_NAT_NO_MAPPING, retries;
	struct ipv4_nat_entry rstate;
	struct ipv4_ct_tuple rtuple;
	__u16 port;
	void *map;

	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;

	snat_v4_swap_tuple(otuple, &rtuple);
	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	rtuple.dport = ostate->to_sport = bpf_htons(port);
	rtuple.daddr = target->addr;

	ostate->common.needs_ct = needs_ct;
	rstate.common.needs_ct = needs_ct;

	map = get_cluster_snat_map_v4(target->cluster_id);
	if (!map)
		return DROP_SNAT_NO_MAP_FOUND;

#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		if (!__snat_lookup(map, &rtuple)) {
			ostate->common.created = bpf_mono_now();
			rstate.common.created = ostate->common.created;

			ret = __snat_update(map, otuple, ostate, &rtuple, &rstate);
			if (!ret)
				break;
		}

		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
		rtuple.dport = ostate->to_sport = bpf_htons(port);
	}

	if (retries > SNAT_SIGNAL_THRES)
		send_signal_nat_fill_up(ctx, SIGNAL_PROTO_V4);

	if (ret < 0) {
		if (ext_err)
			*ext_err = (__s8)ret;
		return DROP_NAT_NO_MAPPING;
	}

	return 0;
}

static __always_inline int
snat_v4_nat_handle_mapping(struct __ctx_buff *ctx,
			   struct ipv4_ct_tuple *tuple,
			   bool has_l4_header,
			   enum ct_action ct_action,
			   struct ipv4_nat_entry **state,
			   struct ipv4_nat_entry *tmp,
			   __u32 off,
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

		/* CT expects a tuple with the source and destination ports reversed,
		 * while NAT uses normal tuples that match packet headers.
		 */
		ipv4_ct_tuple_swap_ports(&tuple_snat);

		ret = ct_lazy_lookup4(get_ct_map4(&tuple_snat), &tuple_snat,
				      ctx, off, has_l4_header, ct_action, CT_EGRESS,
				      SCOPE_FORWARD, &ct_state, &trace->monitor);
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
		return NAT_CONTINUE_XLATE;
	else
		return snat_v4_new_mapping(ctx, tuple, (*state = tmp), target, needs_ct,
					   ext_err);
}

static __always_inline int
snat_v4_rev_nat_handle_mapping(struct __ctx_buff *ctx,
			       struct ipv4_ct_tuple *tuple,
			       bool has_l4_header,
			       enum ct_action ct_action,
			       struct ipv4_nat_entry **state,
			       __u32 off,
			       const struct ipv4_nat_target *target)
{
	void *map;

	map = get_cluster_snat_map_v4(target->cluster_id);
	if (!map)
		return DROP_SNAT_NO_MAP_FOUND;

	*state = __snat_lookup(map, tuple);

	if (*state && (*state)->common.needs_ct) {
		struct ipv4_ct_tuple tuple_revsnat;
		struct ct_state ct_state = {};
		__u32 monitor = 0;
		int ret;

		memcpy(&tuple_revsnat, tuple, sizeof(tuple_revsnat));
		tuple_revsnat.daddr = (*state)->to_daddr;
		tuple_revsnat.dport = (*state)->to_dport;

		/* CT expects a tuple with the source and destination ports reversed,
		 * while NAT uses normal tuples that match packet headers.
		 */
		ipv4_ct_tuple_swap_ports(&tuple_revsnat);

		ret = ct_lazy_lookup4(get_ct_map4(&tuple_revsnat), &tuple_revsnat,
				      ctx, off, has_l4_header, ct_action, CT_INGRESS,
				      SCOPE_REVERSE, &ct_state, &monitor);
		if (ret < 0)
			return ret;
	}

	if (*state)
		return NAT_CONTINUE_XLATE;
	else
		return tuple->nexthdr != IPPROTO_ICMP &&
		       bpf_ntohs(tuple->dport) < target->min_port ?
		       NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;
}

static __always_inline int
snat_v4_icmp_rewrite_ingress_embedded(struct __ctx_buff *ctx,
				      struct ipv4_ct_tuple *tuple,
				      struct ipv4_nat_entry *state,
				      __u32 l4_off, __u32 inner_l4_off)
{
	struct csum_offset csum = {};
	__be32 sum;

	if (state->to_daddr == tuple->daddr &&
	    state->to_dport == tuple->dport)
		return 0;

	sum = csum_diff(&tuple->daddr, 4, &state->to_daddr, 4, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_dport != tuple->dport) {
		__be32 suml4 = 0;

		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			/* In case that the destination port has been NATed from
			 * target to dest. We want the embedded packet which
			 * should refer to endpoint dest going back to original.
			 */
			if (ctx_store_bytes(ctx, inner_l4_off +
					    offsetof(struct tcphdr, source),
					    &state->to_dport,
					    sizeof(state->to_dport), 0) < 0)
				return DROP_WRITE_ERROR;
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
		case IPPROTO_ICMP: {
			/* In case that the ID has been used as source port during
			 * NAT from target to dest. We want the embedded packet
			 * which should refer to endpoint -> dest going back to
			 * original.
			 */
			if (ctx_store_bytes(ctx, inner_l4_off +
					    offsetof(struct icmphdr, un.echo.id),
					    &state->to_dport,
					    sizeof(state->to_dport), 0) < 0)
				return DROP_WRITE_ERROR;
			csum.offset = offsetof(struct icmphdr, checksum);
			csum.flags = 0;
			break;
		}
		default:
			return DROP_UNKNOWN_L4;
		}
		/* By recomputing L4 checksum of inner packet we avoid having
		 * to recompute L4 of the ICMP Error.
		 */
		suml4 = csum_diff(&tuple->dport, 4, &state->to_dport, 4, 0);
		if (csum_l4_replace(ctx, inner_l4_off, &csum, 0, suml4, 0) < 0)
			return DROP_CSUM_L4;
	}
	/* Change IP of source address of inner packet to refer the
	 * endpoint and update csum accordinly.
	 */
	if (ctx_store_bytes(ctx, l4_off + sizeof(struct icmphdr) + offsetof(struct iphdr, saddr),
			    &state->to_daddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ipv4_csum_update_by_diff(ctx, l4_off + sizeof(struct icmphdr), sum) < 0)
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

static __always_inline int snat_v4_rewrite_egress(struct __ctx_buff *ctx,
						  struct ipv4_ct_tuple *tuple,
						  struct ipv4_nat_entry *state,
						  __u32 off, bool has_l4_header)
{
	int ret, flags = BPF_F_PSEUDO_HDR;
	struct csum_offset csum = {};
	__be32 sum;

	if (state->to_saddr == tuple->saddr &&
	    state->to_sport == tuple->sport)
		return 0;
	sum = csum_diff(&tuple->saddr, 4, &state->to_saddr, 4, 0);
	if (has_l4_header) {
		csum_l4_offset_and_flags(tuple->nexthdr, &csum);

		if (state->to_sport != tuple->sport) {
			switch (tuple->nexthdr) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				ret = l4_modify_port(ctx, off,
						     offsetof(struct tcphdr, source),
						     &csum, state->to_sport,
						     tuple->sport);
				if (ret < 0)
					return ret;
				break;
#ifdef ENABLE_SCTP
			case IPPROTO_SCTP:
				return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
			case IPPROTO_ICMP: {
				if (ctx_store_bytes(ctx, off +
						    offsetof(struct icmphdr, un.echo.id),
						    &state->to_sport,
						    sizeof(state->to_sport), 0) < 0)
					return DROP_WRITE_ERROR;
				if (l4_csum_replace(ctx, off + offsetof(struct icmphdr, checksum),
						    tuple->sport,
						    state->to_sport,
						    sizeof(tuple->sport)) < 0)
					return DROP_CSUM_L4;
				break;
			}}
		}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr),
			    &state->to_saddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ipv4_csum_update_by_diff(ctx, ETH_HLEN, sum) < 0)
		return DROP_CSUM_L3;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

static __always_inline int snat_v4_rewrite_ingress(struct __ctx_buff *ctx,
						   struct ipv4_ct_tuple *tuple,
						   struct ipv4_nat_entry *state,
						   __u32 off)
{
	int ret, flags = BPF_F_PSEUDO_HDR;
	struct csum_offset csum = {};
	__be32 sum;

	if (state->to_daddr == tuple->daddr &&
	    state->to_dport == tuple->dport)
		return 0;
	sum = csum_diff(&tuple->daddr, 4, &state->to_daddr, 4, 0);
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
		case IPPROTO_ICMP: {
			__u8 type = 0;

			if (ctx_load_bytes(ctx, off +
					   offsetof(struct icmphdr, type),
					   &type, 1) < 0)
				return DROP_INVALID;
			if (type == ICMP_ECHO || type == ICMP_ECHOREPLY) {
				if (ctx_store_bytes(ctx, off +
						    offsetof(struct icmphdr, un.echo.id),
						    &state->to_dport,
						    sizeof(state->to_dport), 0) < 0)
					return DROP_WRITE_ERROR;
				if (l4_csum_replace(ctx, off + offsetof(struct icmphdr, checksum),
						    tuple->dport,
						    state->to_dport,
						    sizeof(tuple->dport)) < 0)
					return DROP_CSUM_L4;
			}
			break;
		}}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr),
			    &state->to_daddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ipv4_csum_update_by_diff(ctx, ETH_HLEN, sum) < 0)
		return DROP_CSUM_L3;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

static __always_inline bool
snat_v4_nat_can_skip(const struct ipv4_nat_target *target, const struct ipv4_ct_tuple *tuple,
		     bool icmp_echoreply)
{
	__u16 sport = bpf_ntohs(tuple->sport);

#if defined(ENABLE_EGRESS_GATEWAY)
	if (target->egress_gateway)
		return false;
#endif

	return (!target->from_local_endpoint && !target->src_from_world &&
		sport < NAT_MIN_EGRESS) ||
		icmp_echoreply;
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
 * The function will return true if the packet should be SNAT-ed, false
 * otherwise.
 */
static __always_inline bool snat_v4_prepare_state(struct __ctx_buff *ctx,
						  struct ipv4_nat_target *target)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct endpoint_info *local_ep __maybe_unused;
	struct remote_endpoint_info *remote_ep __maybe_unused;
	struct egress_gw_policy_entry *egress_gw_policy __maybe_unused;
	bool is_reply = false;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return false;

	/* Basic minimum is to only NAT when there is a potential of
	 * overlapping tuples, e.g. applications in hostns reusing
	 * source IPs we SNAT in NodePort and BPF-masq.
	 */
#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	if (ip4->saddr == IPV4_GATEWAY) {
		target->addr = IPV4_GATEWAY;
		target->needs_ct = true;

		return true;
	}

# if defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && defined(ENABLE_INTER_CLUSTER_SNAT)
	if (target->cluster_id != 0 &&
	    target->cluster_id != CLUSTER_ID) {
		target->addr = IPV4_INTER_CLUSTER_SNAT;
		return true;
	}
# endif
#else
    /* NATIVE_DEV_IFINDEX == DIRECT_ROUTING_DEV_IFINDEX cannot be moved into
     * preprocessor, as the former is known only during load time (templating).
     * This checks whether bpf_host is running on the direct routing device.
     */
	if (DIRECT_ROUTING_DEV_IFINDEX == NATIVE_DEV_IFINDEX &&
	    ip4->saddr == IPV4_DIRECT_ROUTING) {
		target->addr = IPV4_DIRECT_ROUTING;
		target->needs_ct = true;

		return true;
	}
# ifdef ENABLE_MASQUERADE_IPV4
	if (ip4->saddr == IPV4_MASQUERADE) {
		target->addr = IPV4_MASQUERADE;
		target->needs_ct = true;

		return true;
	}
# endif /* ENABLE_MASQUERADE_IPV4 */
#endif /* defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY) */

	local_ep = __lookup_ip4_endpoint(ip4->saddr);
	remote_ep = lookup_ip4_remote_endpoint(ip4->daddr, 0);

	/* Check if this packet belongs to reply traffic coming from a
	 * local endpoint.
	 *
	 * If local_ep is NULL, it means there's no endpoint running on the
	 * node which matches the packet source IP, which means we can
	 * skip the CT lookup since this cannot be reply traffic.
	 */
	if (local_ep) {
		struct ipv4_ct_tuple tuple = {
			.nexthdr = ip4->protocol,
			.daddr = ip4->daddr,
			.saddr = ip4->saddr
		};

		target->from_local_endpoint = true;

		ct_is_reply4(get_ct_map4(&tuple), ctx, ETH_HLEN +
			     ipv4_hdrlen(ip4), &tuple, &is_reply);
	}

#ifdef ENABLE_MASQUERADE_IPV4 /* SNAT local pod to world packets */
# ifdef IS_BPF_OVERLAY
	/* Do not MASQ when this function is executed from bpf_overlay
	 * (IS_BPF_OVERLAY denotes this fact). Otherwise, a packet will
	 * be SNAT'd to cilium_host IP addr.
	 */
	return false;
# endif

/* Check if the packet matches an egress NAT policy and so needs to be SNAT'ed.
 *
 * This check must happen before the IPV4_SNAT_EXCLUSION_DST_CIDR check below as
 * the destination may be in the SNAT exclusion CIDR but regardless of that we
 * always want to SNAT a packet if it's matched by an egress NAT policy.
 */
#if defined(ENABLE_EGRESS_GATEWAY)
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

	if (egress_gw_snat_needed(ip4, &target->addr)) {
		target->egress_gateway = true;
		/* If the endpoint is local, then the connection is already tracked. */
		if (!local_ep)
			target->needs_ct = true;

		return true;
	}
skip_egress_gateway:
#endif

#ifdef IPV4_SNAT_EXCLUSION_DST_CIDR
	/* Do not MASQ if a dst IP belongs to a pods CIDR
	 * (ipv4-native-routing-cidr if specified, otherwise local pod CIDR).
	 * The check is performed before we determine that a packet is
	 * sent from a local pod, as this check is cheaper than
	 * the map lookup done in the latter check.
	 */
	if (ipv4_is_in_subnet(ip4->daddr, IPV4_SNAT_EXCLUSION_DST_CIDR,
			      IPV4_SNAT_EXCLUSION_DST_CIDR_LEN))
		return false;
#endif

	/* if this is a localhost endpoint, no SNAT is needed */
	if (local_ep && (local_ep->flags & ENDPOINT_F_HOST))
		return false;

	if (remote_ep) {
#ifdef ENABLE_IP_MASQ_AGENT_IPV4
		/* Do not SNAT if dst belongs to any ip-masq-agent
		 * subnet.
		 */
		struct lpm_v4_key pfx;

		pfx.lpm.prefixlen = 32;
		memcpy(pfx.lpm.data, &ip4->daddr, sizeof(pfx.addr));
		if (map_lookup_elem(&IP_MASQ_AGENT_IPV4, &pfx))
			return false;
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
			return false;
#endif

		/* If the packet is a reply it means that outside has
		 * initiated the connection, so no need to SNAT the
		 * reply.
		 */
		if (!is_reply && local_ep) {
			target->addr = IPV4_MASQUERADE;
			return true;
		}
	}
#endif /*ENABLE_MASQUERADE_IPV4 */

	return false;
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

	/* Switch back to the outer header. */
	tuple.nexthdr = IPPROTO_ICMP;
	/* Reset so no l4 NAT is done in snat_v4_rewrite_egress. We don't need
	 * it because we are handling ICMP_DEST_UNREACH which doesn't have id.
	 */
	tuple.sport = state->to_sport;

	return snat_v4_rewrite_egress(ctx, &tuple, state, off, has_l4_header);
}

static __always_inline int
__snat_v4_nat(struct __ctx_buff *ctx, struct ipv4_ct_tuple *tuple,
	      bool has_l4_header, int l4_off, enum ct_action action,
	      bool update_tuple, const struct ipv4_nat_target *target,
	      struct trace_ctx *trace, __s8 *ext_err)
{
	struct ipv4_nat_entry *state, tmp;
	int ret;

	ret = snat_v4_nat_handle_mapping(ctx, tuple, has_l4_header, action,
					 &state, &tmp, l4_off, target,
					 trace, ext_err);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

	ret = snat_v4_rewrite_egress(ctx, tuple, state, l4_off, has_l4_header);

	if (update_tuple) {
		tuple->saddr = state->to_saddr;
		tuple->sport = state->to_sport;
	}

	return ret;
}

static __always_inline __maybe_unused int
snat_v4_nat(struct __ctx_buff *ctx, const struct ipv4_nat_target *target,
	    struct trace_ctx *trace, __s8 *ext_err)
{
	enum ct_action ct_action = ACTION_UNSPEC;
	struct icmphdr icmphdr __align_stack_8;
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	bool icmp_echoreply = false;
	bool has_l4_header;
	__u64 off;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &tuple);
	has_l4_header = ipv4_has_l4_header(ip4);

	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
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
		ct_action = ACTION_CREATE;
		break;
	case IPPROTO_ICMP:
		if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;

		switch (icmphdr.type) {
		case ICMP_ECHO:
			tuple.dport = 0;
			tuple.sport = icmphdr.un.echo.id;
			ct_action = ACTION_CREATE;
			break;
		case ICMP_ECHOREPLY:
			tuple.dport = icmphdr.un.echo.id;
			tuple.sport = 0;
			icmp_echoreply = true;
			break;
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

	if (snat_v4_nat_can_skip(target, &tuple, icmp_echoreply))
		return NAT_PUNT_TO_STACK;

	return __snat_v4_nat(ctx, &tuple, has_l4_header, off, ct_action,
			     false, target, trace, ext_err);
}

static __always_inline __maybe_unused int
snat_v4_rev_nat_handle_icmp_frag_needed(struct __ctx_buff *ctx, __u64 off)
{
	struct ipv4_ct_tuple tuple = {};
	struct ipv4_nat_entry *state;
	struct iphdr iphdr;
	__be16 identifier;
	__u8 type;
	__u32 icmpoff = off + sizeof(struct icmphdr);
	int ret;

	/* According to the RFC 5508, any networking equipment that is
	 * responding with an ICMP Error packet should embed the original
	 * packet in its response.
	 */

	if (ctx_load_bytes(ctx, icmpoff, &iphdr,
			   sizeof(iphdr)) < 0)
		return DROP_INVALID;

	/* From the embedded IP headers we should be able to determine
	 * corresponding protocol, IP src/dst of the packet sent to resolve the
	 * NAT session.
	 */
	tuple.nexthdr = iphdr.protocol;
	tuple.saddr = iphdr.daddr;
	tuple.daddr = iphdr.saddr;
	tuple.flags = NAT_DIR_INGRESS;

	icmpoff += ipv4_hdrlen(&iphdr);
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
		break;
	case IPPROTO_ICMP:
		/* No reasons to see a packet different than ICMP_ECHO. */
		if (ctx_load_bytes(ctx, icmpoff, &type, sizeof(type)) < 0 ||
		    type != ICMP_ECHO)
			return DROP_INVALID;
		if (ctx_load_bytes(ctx, icmpoff +
				   offsetof(struct icmphdr, un.echo.id),
				   &identifier, sizeof(identifier)) < 0)
			return DROP_INVALID;
		tuple.sport = 0;
		tuple.dport = identifier;
		break;
	default:
		return NAT_PUNT_TO_STACK;
	}
	state = snat_v4_lookup(&tuple);
	if (!state)
		return NAT_PUNT_TO_STACK;

	/* We found SNAT entry to rev-NAT embedded packet. The source addr
	 * should point to endpoint that initiated the packet, as-well if
	 * dest port had been NATed.
	 */
	ret = snat_v4_icmp_rewrite_ingress_embedded(ctx, &tuple, state,
						    off, icmpoff);
	if (IS_ERR(ret))
		return ret;

	/* Switch back to the outer header. */
	tuple.nexthdr = IPPROTO_ICMP;

	return snat_v4_rewrite_ingress(ctx, &tuple, state, off);
}

static __always_inline __maybe_unused int
snat_v4_rev_nat(struct __ctx_buff *ctx, const struct ipv4_nat_target *target,
		__s8 *ext_err __maybe_unused)
{
	enum ct_action ct_action = ACTION_UNSPEC;
	struct icmphdr icmphdr __align_stack_8;
	struct ipv4_nat_entry *state;
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	bool has_l4_header = true;
	__u64 off;
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
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		ct_action = ACTION_CREATE;
		break;
	case IPPROTO_ICMP:
		if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;
		switch (icmphdr.type) {
		case ICMP_ECHO:
			tuple.dport = 0;
			tuple.sport = icmphdr.un.echo.id;
			ct_action = ACTION_CREATE;
			break;
		case ICMP_ECHOREPLY:
			tuple.dport = icmphdr.un.echo.id;
			tuple.sport = 0;
			break;
		case ICMP_DEST_UNREACH:
			if (icmphdr.code != ICMP_FRAG_NEEDED)
				return NAT_PUNT_TO_STACK;
			return snat_v4_rev_nat_handle_icmp_frag_needed(ctx, off);
		default:
			return NAT_PUNT_TO_STACK;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v4_rev_nat_can_skip(target, &tuple))
		return NAT_PUNT_TO_STACK;
	ret = snat_v4_rev_nat_handle_mapping(ctx, &tuple, has_l4_header, ct_action, &state,
					     off, target);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

	return snat_v4_rewrite_ingress(ctx, &tuple, state, off);
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
	bool src_from_world;
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

static __always_inline void snat_v6_swap_tuple(const struct ipv6_ct_tuple *otuple,
					       struct ipv6_ct_tuple *rtuple)
{
	memset(rtuple, 0, sizeof(*rtuple));
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->daddr = otuple->saddr;
	rtuple->saddr = otuple->daddr;
	rtuple->dport = otuple->sport;
	rtuple->sport = otuple->dport;
	rtuple->flags = otuple->flags == NAT_DIR_EGRESS ?
			NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

static __always_inline int snat_v6_new_mapping(struct __ctx_buff *ctx,
					       struct ipv6_ct_tuple *otuple,
					       struct ipv6_nat_entry *ostate,
					       const struct ipv6_nat_target *target,
					       bool needs_ct, __s8 *ext_err)
{
	int ret = DROP_NAT_NO_MAPPING, retries;
	struct ipv6_nat_entry rstate;
	struct ipv6_ct_tuple rtuple;
	__u16 port;

	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;

	snat_v6_swap_tuple(otuple, &rtuple);
	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	rtuple.dport = ostate->to_sport = bpf_htons(port);
	rtuple.daddr = target->addr;

	ostate->common.needs_ct = needs_ct;
	rstate.common.needs_ct = needs_ct;

#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		if (!snat_v6_lookup(&rtuple)) {
			ostate->common.created = bpf_mono_now();
			rstate.common.created = ostate->common.created;

			ret = snat_v6_update(otuple, ostate, &rtuple, &rstate);
			if (!ret)
				break;
		}

		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
		rtuple.dport = ostate->to_sport = bpf_htons(port);
	}

	if (retries > SNAT_SIGNAL_THRES)
		send_signal_nat_fill_up(ctx, SIGNAL_PROTO_V6);

	if (ret < 0) {
		if (ext_err)
			*ext_err = (__s8)ret;
		return DROP_NAT_NO_MAPPING;
	}

	return 0;
}

static __always_inline int
snat_v6_nat_handle_mapping(struct __ctx_buff *ctx,
			   struct ipv6_ct_tuple *tuple,
			   enum ct_action ct_action,
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
		/* CT expects a tuple with the source and destination ports reversed,
		 * while NAT uses normal tuples that match packet headers.
		 */
		ipv6_ct_tuple_swap_ports(&tuple_snat);

		ret = ct_lazy_lookup6(get_ct_map6(&tuple_snat), &tuple_snat,
				      ctx, off, ct_action, CT_EGRESS,
				      SCOPE_FORWARD, &ct_state, &trace->monitor);
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
		return NAT_CONTINUE_XLATE;
	else
		return snat_v6_new_mapping(ctx, tuple, (*state = tmp), target, needs_ct,
					   ext_err);
}

static __always_inline int
snat_v6_rev_nat_handle_mapping(struct __ctx_buff *ctx,
			       struct ipv6_ct_tuple *tuple,
			       enum ct_action ct_action,
			       struct ipv6_nat_entry **state,
			       __u32 off,
			       const struct ipv6_nat_target *target)
{
	*state = snat_v6_lookup(tuple);

	if (*state && (*state)->common.needs_ct) {
		struct ipv6_ct_tuple tuple_revsnat;
		struct ct_state ct_state = {};
		__u32 monitor = 0;
		int ret;

		memcpy(&tuple_revsnat, tuple, sizeof(tuple_revsnat));
		ipv6_addr_copy(&tuple_revsnat.daddr, &(*state)->to_daddr);
		tuple_revsnat.dport = (*state)->to_dport;

		/* CT expects a tuple with the source and destination ports reversed,
		 * while NAT uses normal tuples that match packet headers.
		 */
		ipv6_ct_tuple_swap_ports(&tuple_revsnat);

		ret = ct_lazy_lookup6(get_ct_map6(&tuple_revsnat), &tuple_revsnat,
				      ctx, off, ct_action, CT_INGRESS,
				      SCOPE_REVERSE, &ct_state, &monitor);
		if (ret < 0)
			return ret;
	}

	if (*state)
		return NAT_CONTINUE_XLATE;
	else
		return tuple->nexthdr != IPPROTO_ICMPV6 &&
		       bpf_ntohs(tuple->dport) < target->min_port ?
		       NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;
}

static __always_inline int snat_v6_icmp_rewrite_embedded(struct __ctx_buff *ctx,
							 struct ipv6_ct_tuple *tuple,
							 struct ipv6_nat_entry *state,
							 __u32 l4_off, __u32 inner_l4_off)
{
	struct csum_offset csum = {};

	if (ipv6_addr_equals(&state->to_daddr, &tuple->daddr) &&
	    state->to_dport == tuple->dport)
		return 0;

	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_dport != tuple->dport) {
		__be32 suml4 = 0;

		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			/* In case that the destination port has been NATed from
			 * target to dest. We want the embedded packet which
			 * should refer to endpoint dest going back to original.
			 */
			if (ctx_store_bytes(ctx, inner_l4_off + offsetof(struct tcphdr, source),
					    &state->to_dport, sizeof(state->to_dport), 0) < 0)
				return DROP_WRITE_ERROR;
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
		case IPPROTO_ICMPV6: {
			/* In case that the ID has been used as source port during
			 * NAT from target to dest. We want the embedded packet
			 * which should refer to endpoint -> dest going back to
			 * original.
			 */
			if (ctx_store_bytes(ctx, inner_l4_off +
					    offsetof(struct icmp6hdr,
						     icmp6_dataun.u_echo.identifier),
					    &state->to_dport,
					    sizeof(state->to_dport), 0) < 0)
				return DROP_WRITE_ERROR;
			break;
		}
		default:
			return DROP_INVALID;
		}
		/* By recomputing L4 checksum of inner packet we avoid having
		 * to recompute L4 of the ICMP Error.
		 */
		suml4 = csum_diff(&tuple->dport, 4, &state->to_dport, 4, 0);
		if (csum_l4_replace(ctx, inner_l4_off, &csum, 0, suml4, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}
	/* Change IP of source address of inner packet to refer the
	 * endpoint.
	 */
	if (ipv6_store_saddr(ctx, (__u8 *)&state->to_daddr,
			     l4_off + sizeof(struct icmp6hdr) - 4) < 0)
		return DROP_WRITE_ERROR;
	return 0;
}

static __always_inline int snat_v6_rewrite_egress(struct __ctx_buff *ctx,
						  struct ipv6_ct_tuple *tuple,
						  struct ipv6_nat_entry *state,
						  __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum;
	int ret;

	if (ipv6_addr_equals(&state->to_saddr, &tuple->saddr) &&
	    state->to_sport == tuple->sport)
		return 0;
	sum = csum_diff(&tuple->saddr, 16, &state->to_saddr, 16, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_sport != tuple->sport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, off, offsetof(struct tcphdr, source),
					     &csum, state->to_sport, tuple->sport);
			if (ret < 0)
				return ret;
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
		case IPPROTO_ICMPV6: {
			__be32 from, to;

			if (ctx_store_bytes(ctx, off +
					    offsetof(struct icmp6hdr,
						     icmp6_dataun.u_echo.identifier),
					    &state->to_sport,
					    sizeof(state->to_sport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->sport;
			to = state->to_sport;
			sum = csum_diff(&from, 4, &to, 4, sum);
			break;
		}}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    &state->to_saddr, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
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

			if (ctx_load_bytes(ctx, off, &type, 1) < 0)
				return DROP_INVALID;
			if (type == ICMPV6_ECHO_REQUEST || type == ICMPV6_ECHO_REPLY) {
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
snat_v6_nat_can_skip(const struct ipv6_nat_target *target, const struct ipv6_ct_tuple *tuple,
		     bool icmp_echoreply)
{
	__u16 sport = bpf_ntohs(tuple->sport);

	return (!target->from_local_endpoint && !target->src_from_world &&
		sport < NAT_MIN_EGRESS) ||
		icmp_echoreply;
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

static __always_inline bool
snat_v6_prepare_state(struct __ctx_buff *ctx, struct ipv6_nat_target *target)
{
	union v6addr masq_addr __maybe_unused, router_ip __maybe_unused;
	const union v6addr dr_addr __maybe_unused = IPV6_DIRECT_ROUTING;
	struct remote_endpoint_info *remote_ep __maybe_unused;
	struct endpoint_info *local_ep;
	bool is_reply = false;
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return false;

#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	BPF_V6(router_ip, ROUTER_IP);
	if (ipv6_addr_equals((union v6addr *)&ip6->saddr, &router_ip)) {
		ipv6_addr_copy(&target->addr, &router_ip);
		target->needs_ct = true;

		return true;
	}
#else
	/* See comment in snat_v4_prepare_state(). */
	if (DIRECT_ROUTING_DEV_IFINDEX == NATIVE_DEV_IFINDEX &&
	    ipv6_addr_equals((union v6addr *)&ip6->saddr, &dr_addr)) {
		ipv6_addr_copy(&target->addr, &dr_addr);
		target->needs_ct = true;

		return true;
	}
# ifdef ENABLE_MASQUERADE_IPV6 /* SNAT local pod to world packets */
	BPF_V6(masq_addr, IPV6_MASQUERADE);
	if (ipv6_addr_equals((union v6addr *)&ip6->saddr, &masq_addr)) {
		ipv6_addr_copy(&target->addr, &masq_addr);
		target->needs_ct = true;

		return true;
	}
# endif /* ENABLE_MASQUERADE_IPV6 */
#endif /* defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY) */

	local_ep = __lookup_ip6_endpoint((union v6addr *)&ip6->saddr);
	remote_ep = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);

	/* See comment in snat_v4_prepare_state(). */
	if (local_ep) {
		struct ipv6_ct_tuple tuple = {};
		int l4_off;

		tuple.nexthdr = ip6->nexthdr;
		ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);
		ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);

		target->from_local_endpoint = true;

		/* ipv6_hdrlen() can return an error. If it does, it makes no
		 * sense marking this packet as a reply based on a wrong offset.
		 *
		 * We should probably improve this code in the future to
		 * report the error to the caller. Same thing for errors
		 * from ct_is_reply6() below, and ct_is_reply4() in
		 * snat_v4_prepare_state().
		 */
		l4_off = ipv6_hdrlen(ctx, &tuple.nexthdr);
		if (l4_off >= 0) {
			l4_off += ETH_HLEN;
			ct_is_reply6(get_ct_map6(&tuple), ctx, l4_off, &tuple,
				     &is_reply);
		}
	}

#ifdef ENABLE_MASQUERADE_IPV6
# ifdef IS_BPF_OVERLAY
	/* See comment in snat_v4_prepare_state(). */
	return false;
# endif /* IS_BPF_OVERLAY */

# ifdef IPV6_SNAT_EXCLUSION_DST_CIDR
	{
		union v6addr excl_cidr_mask = IPV6_SNAT_EXCLUSION_DST_CIDR_MASK;
		union v6addr excl_cidr = IPV6_SNAT_EXCLUSION_DST_CIDR;

		/* See comment in snat_v4_prepare_state(). */
		if (ipv6_addr_in_net((union v6addr *)&ip6->daddr, &excl_cidr,
				     &excl_cidr_mask))
			return false;
	}
# endif /* IPV6_SNAT_EXCLUSION_DST_CIDR */

	/* if this is a localhost endpoint, no SNAT is needed */
	if (local_ep && (local_ep->flags & ENDPOINT_F_HOST))
		return false;

	if (remote_ep) {
#ifdef ENABLE_IP_MASQ_AGENT_IPV6
		/* Do not SNAT if dst belongs to any ip-masq-agent subnet. */
		struct lpm_v6_key pfx __align_stack_8;

		pfx.lpm.prefixlen = sizeof(pfx.addr) * 8;
		/* pfx.lpm is aligned on 8 bytes on the stack, but pfx.lpm.data
		 * is on 4 (after pfx.lpm.prefixlen), and we can't use memcpy()
		 * on the whole field or the verifier complains.
		 */
		memcpy(pfx.lpm.data, &ip6->daddr, 4);
		memcpy(pfx.lpm.data + 4, (__u8 *)&ip6->daddr + 4, 8);
		memcpy(pfx.lpm.data + 12, (__u8 *)&ip6->daddr + 12, 4);
		if (map_lookup_elem(&IP_MASQ_AGENT_IPV6, &pfx))
			return false;
#endif

# ifndef TUNNEL_MODE
		/* See comment in snat_v4_prepare_state(). */
		if (identity_is_remote_node(remote_ep->sec_identity))
			return false;
# endif /* TUNNEL_MODE */

		/* See comment in snat_v4_prepare_state(). */
		if (!is_reply && local_ep) {
			ipv6_addr_copy(&target->addr, &masq_addr);
			return true;
		}
	}
#endif /* ENABLE_MASQUERADE_IPV6 */

	return false;
}

static __always_inline int
__snat_v6_nat(struct __ctx_buff *ctx, struct ipv6_ct_tuple *tuple,
	      int l4_off, enum ct_action action, bool update_tuple,
	      const struct ipv6_nat_target *target,
	      struct trace_ctx *trace, __s8 *ext_err)
{
	struct ipv6_nat_entry *state, tmp;
	int ret;

	ret = snat_v6_nat_handle_mapping(ctx, tuple, action, &state, &tmp,
					 l4_off, target, trace, ext_err);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

	ret = snat_v6_rewrite_egress(ctx, tuple, state, l4_off);

	if (update_tuple) {
		ipv6_addr_copy(&tuple->saddr, &state->to_saddr);
		tuple->sport = state->to_sport;
	}

	return ret;
}

static __always_inline __maybe_unused int
snat_v6_nat(struct __ctx_buff *ctx, const struct ipv6_nat_target *target,
	    struct trace_ctx *trace, __s8 *ext_err)
{
	enum ct_action ct_action = ACTION_UNSPEC;
	struct icmp6hdr icmp6hdr __align_stack_8;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int hdrlen;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u32 off;
	bool icmp_echoreply = false;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	snat_v6_init_tuple(ip6, NAT_DIR_EGRESS, &tuple);

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
		ct_action = ACTION_CREATE;
		break;
	case IPPROTO_ICMPV6:
		if (ctx_load_bytes(ctx, off, &icmp6hdr, sizeof(icmp6hdr)) < 0)
			return DROP_INVALID;
		/* Letting neighbor solicitation / advertisement pass through. */
		if (icmp6hdr.icmp6_type == ICMP6_NS_MSG_TYPE ||
		    icmp6hdr.icmp6_type == ICMP6_NA_MSG_TYPE)
			return CTX_ACT_OK;
		if (icmp6hdr.icmp6_type != ICMPV6_ECHO_REQUEST &&
		    icmp6hdr.icmp6_type != ICMPV6_ECHO_REPLY)
			return DROP_NAT_UNSUPP_PROTO;
		if (icmp6hdr.icmp6_type == ICMPV6_ECHO_REQUEST) {
			tuple.dport = 0;
			tuple.sport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			ct_action = ACTION_CREATE;
		} else {
			tuple.dport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			tuple.sport = 0;
			icmp_echoreply = true;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v6_nat_can_skip(target, &tuple, icmp_echoreply))
		return NAT_PUNT_TO_STACK;

	return __snat_v6_nat(ctx, &tuple, off, ct_action, false, target,
			     trace, ext_err);
}

static __always_inline __maybe_unused int
snat_v6_rev_nat_handle_icmp_pkt_toobig(struct __ctx_buff *ctx, __u32 off)
{
	struct ipv6_nat_entry *state;
	struct ipv6_ct_tuple tuple = {};
	struct ipv6hdr iphdr;
	__be16 identifier;
	__u8 type;
	__u32 icmpoff = off;
	int ret, hdrlen;

	/* According to the RFC 5508, any networking
	 * equipment that is responding with an ICMP Error
	 * packet should embed the original packet in its
	 * response.
	 */

	/* Note related to how is computed the offset. The
	 * ICMPV6_PKT_TOOBIG does not include identifer and
	 * sequence in its headers.
	 */
	icmpoff += sizeof(struct icmp6hdr) - field_sizeof(struct icmp6hdr, icmp6_dataun.u_echo);

	if (ctx_load_bytes(ctx, icmpoff, &iphdr,
			   sizeof(iphdr)) < 0)
		return DROP_INVALID;

	/* From the embedded IP headers we should be able
	 * to determine corresponding protocol, IP src/dst
	 * of the packet sent to resolve the NAT session.
	 */

	tuple.nexthdr = iphdr.nexthdr;
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&iphdr.daddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&iphdr.saddr);
	tuple.flags = NAT_DIR_INGRESS;

	hdrlen = ipv6_hdrlen_offset(ctx, &tuple.nexthdr, icmpoff);
	if (hdrlen < 0)
		return hdrlen;

	icmpoff += hdrlen;

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
		break;
	case IPPROTO_ICMPV6:
		/* No reasons to see a packet different than
		 * ICMPV6_ECHO_REQUEST.
		 */
		if (ctx_load_bytes(ctx, icmpoff, &type, sizeof(type)) < 0 ||
		    type != ICMPV6_ECHO_REQUEST)
			return DROP_INVALID;
		if (ctx_load_bytes(ctx, icmpoff +
				   offsetof(struct icmp6hdr,
					    icmp6_dataun.u_echo.identifier),
				   &identifier, sizeof(identifier)) < 0)
			return DROP_INVALID;
		tuple.sport = 0;
		tuple.dport = identifier;
		break;
	default:
		return NAT_PUNT_TO_STACK;
	}
	state = snat_v6_lookup(&tuple);
	if (!state)
		return NAT_PUNT_TO_STACK;

	/* We found SNAT entry to rev-NAT embedded packet. The source addr
	 * should point to endpoint that initiated the packet, as-well if
	 * dest port had been NATed.
	 */
	ret = snat_v6_icmp_rewrite_embedded(ctx, &tuple, state, off, icmpoff);
	if (IS_ERR(ret))
		return ret;

	/* Switch back to the outer header. */
	tuple.nexthdr = IPPROTO_ICMPV6;

	return snat_v6_rewrite_ingress(ctx, &tuple, state, off);
}

static __always_inline __maybe_unused int
snat_v6_rev_nat(struct __ctx_buff *ctx, const struct ipv6_nat_target *target,
		__s8 *ext_err __maybe_unused)
{
	enum ct_action ct_action = ACTION_UNSPEC;
	struct icmp6hdr icmp6hdr __align_stack_8;
	struct ipv6_nat_entry *state;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, hdrlen;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u32 off;

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
		ct_action = ACTION_CREATE;
		break;
	case IPPROTO_ICMPV6:
		if (ctx_load_bytes(ctx, off, &icmp6hdr, sizeof(icmp6hdr)) < 0)
			return DROP_INVALID;
		switch (icmp6hdr.icmp6_type) {
			/* Letting neighbor solicitation / advertisement pass through. */
		case ICMP6_NS_MSG_TYPE:
		case ICMP6_NA_MSG_TYPE:
			return CTX_ACT_OK;
		case ICMPV6_ECHO_REQUEST:
			tuple.dport = 0;
			tuple.sport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			ct_action = ACTION_CREATE;
			break;
		case ICMPV6_ECHO_REPLY:
			tuple.dport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			tuple.sport = 0;
			break;
		case ICMPV6_PKT_TOOBIG:
			return snat_v6_rev_nat_handle_icmp_pkt_toobig(ctx, off);
		default:
			return NAT_PUNT_TO_STACK;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v6_rev_nat_can_skip(target, &tuple))
		return NAT_PUNT_TO_STACK;
	ret = snat_v6_rev_nat_handle_mapping(ctx, &tuple, ct_action, &state,
					     off, target);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

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
