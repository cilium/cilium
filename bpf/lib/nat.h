/*
 *  Copyright (C) 2019 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
/* Simple NAT engine in BPF. */
#ifndef __LIB_NAT__
#define __LIB_NAT__

#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>

#include "common.h"
#include "drop.h"
#include "conntrack.h"
#include "conntrack_map.h"

enum {
	NAT_DIR_EGRESS  = TUPLE_F_OUT,
	NAT_DIR_INGRESS = TUPLE_F_IN,
};

struct nat_entry {
	__u64 created;
	__u64 host_local;	/* Only single bit used. */
	__u64 pad1;		/* Future use. */
	__u64 pad2;		/* Future use. */
};

#define NAT_CONTINUE_XLATE 	0
#define NAT_PUNT_TO_STACK	1

#ifdef HAVE_LRU_MAP_TYPE
#define NAT_MAP_TYPE BPF_MAP_TYPE_LRU_HASH
#else
#define NAT_MAP_TYPE BPF_MAP_TYPE_HASH
#endif

static __always_inline __be16 __snat_clamp_port_range(__u16 start, __u16 end,
						      __u16 val)
{
	return (val % (__u16)(end - start)) + start;
}

#define GOLDEN_RATIO_32 0x61C88647

static __always_inline __be16 __snat_hash(__u16 val)
{
	/* High bits are more random, so use them. */
	return ((__u32)val * GOLDEN_RATIO_32) >> 16;
}

static __always_inline void *__snat_lookup(void *map, void *tuple)
{
	return map_lookup_elem(map, tuple);
}

static __always_inline int __snat_update(void *map, void *otuple, void *ostate,
					 void *rtuple, void *rstate)
{
	int ret = map_update_elem(map, rtuple, rstate, BPF_NOEXIST);
	if (!ret) {
		ret = map_update_elem(map, otuple, ostate, BPF_NOEXIST);
		if (ret)
			map_delete_elem(map, rtuple);
	}
	return ret;
}

static __always_inline void __snat_delete(void *map, void *otuple,
					  void *rtuple)
{
	map_delete_elem(map, otuple);
	map_delete_elem(map, rtuple);
}

struct ipv4_nat_entry {
	struct nat_entry common;
	union {
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
	const __u16 min_port; /* host endianess */
	const __u16 max_port; /* host endianess */
	/* Tells whether the port mapping /has/ to be clampled into [min_port,max_port]
	 * range (true) or only in case of collisions (false) where we would first try
	 * to not mange the port, but only remap to the SNAT IP as an optimization.
	 */
	const bool force_range;
};

#if defined ENABLE_IPV4 && (defined ENABLE_MASQUERADE || defined ENABLE_NODEPORT)
struct bpf_elf_map __section_maps SNAT_MAPPING_IPV4 = {
	.type		= NAT_MAP_TYPE,
	.size_key	= sizeof(struct ipv4_ct_tuple),
	.size_value	= sizeof(struct ipv4_nat_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= SNAT_MAPPING_IPV4_SIZE,
#ifndef HAVE_LRU_MAP_TYPE
	.flags		= CONDITIONAL_PREALLOC,
#endif
};

static __always_inline
struct ipv4_nat_entry *snat_v4_lookup(struct ipv4_ct_tuple *tuple)
{
	return __snat_lookup(&SNAT_MAPPING_IPV4, tuple);
}

static __always_inline int snat_v4_update(struct ipv4_ct_tuple *otuple,
					  struct ipv4_nat_entry *ostate,
					  struct ipv4_ct_tuple *rtuple,
					  struct ipv4_nat_entry *rstate)
{
	return __snat_update(&SNAT_MAPPING_IPV4, otuple, ostate,
			     rtuple, rstate);
}

static __always_inline void snat_v4_delete(struct ipv4_ct_tuple *otuple,
					   struct ipv4_ct_tuple *rtuple)
{
	__snat_delete(&SNAT_MAPPING_IPV4, otuple, rtuple);
}

static __always_inline void snat_v4_swap_tuple(struct ipv4_ct_tuple *otuple,
					       struct ipv4_ct_tuple *rtuple)
{
	__builtin_memset(rtuple, 0, sizeof(*rtuple));
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->daddr = otuple->saddr;
	rtuple->saddr = otuple->daddr;
	rtuple->dport = otuple->sport;
	rtuple->sport = otuple->dport;
	rtuple->flags = otuple->flags == NAT_DIR_EGRESS ?
			NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

static __always_inline int snat_v4_reverse_tuple(struct ipv4_ct_tuple *otuple,
						 struct ipv4_ct_tuple *rtuple)
{
	struct ipv4_nat_entry *ostate;

	ostate = snat_v4_lookup(otuple);
	if (ostate) {
		snat_v4_swap_tuple(otuple, rtuple);
		rtuple->daddr = ostate->to_saddr;
		rtuple->dport = ostate->to_sport;
	}

	return ostate ? 0 : -1;
}

static __always_inline void snat_v4_ct_canonicalize(struct ipv4_ct_tuple *otuple)
{
	__be32 addr = otuple->saddr;

	otuple->flags = NAT_DIR_EGRESS;
	/* Workaround #5848. */
	otuple->saddr = otuple->daddr;
	otuple->daddr = addr;
}

static __always_inline void snat_v4_delete_tuples(struct ipv4_ct_tuple *otuple)
{
	struct ipv4_ct_tuple rtuple;

	if (otuple->flags & TUPLE_F_IN)
		return;
	snat_v4_ct_canonicalize(otuple);
	if (!snat_v4_reverse_tuple(otuple, &rtuple))
		snat_v4_delete(otuple, &rtuple);
}

static __always_inline int snat_v4_new_mapping(struct __sk_buff *skb,
					       struct ipv4_ct_tuple *otuple,
					       struct ipv4_nat_entry *ostate,
					       const struct ipv4_nat_target *target)
{
	bool initial_port_in_range = !target->force_range;
	struct ipv4_nat_entry rstate;
	struct ipv4_ct_tuple rtuple;
	int ret, retries;
	__be16 port;

	__builtin_memset(&rstate, 0, sizeof(rstate));
	__builtin_memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;
	ostate->to_sport = otuple->sport;

	snat_v4_swap_tuple(otuple, &rtuple);
	rtuple.daddr = target->addr;

	if (otuple->saddr == target->addr) {
		ostate->common.host_local = 1;
		rstate.common.host_local = ostate->common.host_local;
	}

	port = bpf_ntohs(rtuple.dport);
	if (target->force_range &&
	    port >= target->min_port && port <= target->max_port)
		initial_port_in_range = true;
#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		if (retries == 0 && !initial_port_in_range)
			goto select_port;
		if (!snat_v4_lookup(&rtuple)) {
			ostate->common.created = bpf_ktime_get_nsec();
			rstate.common.created = ostate->common.created;

			ret = snat_v4_update(otuple, ostate, &rtuple, &rstate);
			if (!ret)
				return 0;
		}
select_port:
		if (NAT_MAP_TYPE == BPF_MAP_TYPE_LRU_HASH &&
		    retries < SNAT_DETERMINISTIC_RETRIES)
			port = __snat_hash(rtuple.dport);
		else
			port = get_prandom_u32();
		port = __snat_clamp_port_range(target->min_port,
					       target->max_port, port);
		rtuple.dport = ostate->to_sport = bpf_htons(port);
	}

	return DROP_NAT_NO_MAPPING;
}

static __always_inline int snat_v4_track_local(struct __sk_buff *skb,
					       struct ipv4_ct_tuple *tuple,
					       struct ipv4_nat_entry *state,
					       int dir, __u32 off,
					       const struct ipv4_nat_target *target)
{
	struct ct_state ct_state;
	struct ipv4_ct_tuple tmp;
	bool needs_ct = false;
	__u32 monitor = 0;
	int ret, where;

	if (state && state->common.host_local) {
		needs_ct = true;
	} else if (!state && dir == NAT_DIR_EGRESS) {
		if (tuple->saddr == target->addr)
			needs_ct = true;
	}
	if (!needs_ct)
		return 0;

	__builtin_memset(&ct_state, 0, sizeof(ct_state));
	__builtin_memcpy(&tmp, tuple, sizeof(tmp));

	where = dir == NAT_DIR_INGRESS ? CT_INGRESS : CT_EGRESS;

	ret = ct_lookup4(get_ct_map4(&tmp), &tmp, skb, off, where,
			 &ct_state, &monitor);
	if (ret < 0) {
		return ret;
	} else if (ret == CT_NEW) {
		ret = ct_create4(get_ct_map4(&tmp), &tmp, skb, where,
				 &ct_state, false);
		if (IS_ERR(ret))
			return ret;
	}

	return 0;
}

static __always_inline int snat_v4_handle_mapping(struct __sk_buff *skb,
						  struct ipv4_ct_tuple *tuple,
						  struct ipv4_nat_entry **state,
						  struct ipv4_nat_entry *tmp,
						  int dir, __u32 off,
						  const struct ipv4_nat_target *target)
{
	int ret;

	*state = snat_v4_lookup(tuple);
	ret = snat_v4_track_local(skb, tuple, *state, dir, off, target);
	if (ret < 0)
		return ret;
	else if (*state)
		return NAT_CONTINUE_XLATE;
	else if (dir == NAT_DIR_INGRESS)
		return tuple->nexthdr != IPPROTO_ICMP &&
		       bpf_ntohs(tuple->dport) < target->min_port ?
		       NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;
	else
		return snat_v4_new_mapping(skb, tuple, (*state = tmp), target);
}

static __always_inline int snat_v4_rewrite_egress(struct __sk_buff *skb,
						  struct ipv4_ct_tuple *tuple,
						  struct ipv4_nat_entry *state,
						  __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum_l4 = 0, sum;
	int ret;

	if (state->to_saddr == tuple->saddr &&
	    state->to_sport == tuple->sport)
		return 0;
	sum = csum_diff(&tuple->saddr, 4, &state->to_saddr, 4, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_sport != tuple->sport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(skb, off,
					     offsetof(struct tcphdr, source),
					     &csum, state->to_sport,
					     tuple->sport);
			if (ret < 0)
				return ret;
			break;
		case IPPROTO_ICMP: {
			__be32 from, to;

			if (skb_store_bytes(skb, off +
					    offsetof(struct icmphdr, un.echo.id),
					    &state->to_sport,
					    sizeof(state->to_sport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->sport;
			to = state->to_sport;
			sum_l4 = csum_diff(&from, 4, &to, 4, 0);
			csum.offset = offsetof(struct icmphdr, checksum);
			break;
		}}
	}
	if (skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr),
			    &state->to_saddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	if (tuple->nexthdr == IPPROTO_ICMP)
		sum = sum_l4;
	if (csum.offset &&
	    csum_l4_replace(skb, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
                return DROP_CSUM_L4;
	return 0;
}

static __always_inline int snat_v4_rewrite_ingress(struct __sk_buff *skb,
						   struct ipv4_ct_tuple *tuple,
						   struct ipv4_nat_entry *state,
						   __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum_l4 = 0, sum;
	int ret;

	if (state->to_daddr == tuple->daddr &&
	    state->to_dport == tuple->dport)
		return 0;
	sum = csum_diff(&tuple->daddr, 4, &state->to_daddr, 4, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_dport != tuple->dport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(skb, off,
					     offsetof(struct tcphdr, dest),
					     &csum, state->to_dport,
					     tuple->dport);
			if (ret < 0)
				return ret;
			break;
		case IPPROTO_ICMP: {
			__be32 from, to;

			if (skb_store_bytes(skb, off +
					    offsetof(struct icmphdr, un.echo.id),
					    &state->to_dport,
					    sizeof(state->to_dport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->dport;
			to = state->to_dport;
			sum_l4 = csum_diff(&from, 4, &to, 4, 0);
			csum.offset = offsetof(struct icmphdr, checksum);
			break;
		}}
	}
	if (skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr),
			    &state->to_daddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	if (tuple->nexthdr == IPPROTO_ICMP)
		sum = sum_l4;
	if (csum.offset &&
	    csum_l4_replace(skb, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
                return DROP_CSUM_L4;
	return 0;
}

static __always_inline bool snat_v4_can_skip(const struct ipv4_nat_target *target,
					     const struct ipv4_ct_tuple *tuple, int dir)
{
	__u16 dport = bpf_ntohs(tuple->dport), sport = bpf_ntohs(tuple->sport);

	if (dir == NAT_DIR_EGRESS && sport < NAT_MIN_EGRESS)
		return true;
	if (dir == NAT_DIR_INGRESS && (dport < target->min_port || dport > target->max_port))
		return true;
	return false;
}

static __always_inline int snat_v4_process(struct __sk_buff *skb, int dir,
					   const struct ipv4_nat_target *target)
{
	struct ipv4_nat_entry *state, tmp;
	struct ipv4_ct_tuple tuple = {};
	struct icmphdr icmphdr;
	void *data, *data_end;
	struct iphdr *ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u32 off;
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	tuple.flags = dir;
	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (skb_load_bytes(skb, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		break;
	case IPPROTO_ICMP:
		if (skb_load_bytes(skb, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;
		if (icmphdr.type != ICMP_ECHO &&
		    icmphdr.type != ICMP_ECHOREPLY)
			return DROP_NAT_UNSUPP_PROTO;
		if (dir == NAT_DIR_EGRESS) {
			tuple.dport = 0;
			tuple.sport = icmphdr.un.echo.id;
		} else {
			tuple.dport = icmphdr.un.echo.id;
			tuple.sport = 0;
		}
		break;
	default:
		return DROP_NAT_UNSUPP_PROTO;
	};

	if (target->force_range && snat_v4_can_skip(target, &tuple, dir))
		return TC_ACT_OK;
	ret = snat_v4_handle_mapping(skb, &tuple, &state, &tmp, dir, off, target);
	if (ret > 0)
		return TC_ACT_OK;
	if (ret < 0)
		return ret;

	return dir == NAT_DIR_EGRESS ?
	       snat_v4_rewrite_egress(skb, &tuple, state, off) :
	       snat_v4_rewrite_ingress(skb, &tuple, state, off);
}
#else
static __always_inline int snat_v4_process(struct __sk_buff *skb, int dir,
					   const struct ipv4_nat_target *target)
{
	return TC_ACT_OK;
}

static __always_inline void snat_v4_delete_tuples(struct ipv4_ct_tuple *tuple)
{
}
#endif

struct ipv6_nat_entry {
	struct nat_entry common;
	union {
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
	const __u16 min_port; /* host endianess */
	const __u16 max_port; /* host endianess */
	const bool force_range;
};

#if defined ENABLE_IPV6 && (defined ENABLE_MASQUERADE || defined ENABLE_NODEPORT)
struct bpf_elf_map __section_maps SNAT_MAPPING_IPV6 = {
	.type		= NAT_MAP_TYPE,
	.size_key	= sizeof(struct ipv6_ct_tuple),
	.size_value	= sizeof(struct ipv6_nat_entry),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= SNAT_MAPPING_IPV6_SIZE,
#ifndef HAVE_LRU_MAP_TYPE
	.flags		= CONDITIONAL_PREALLOC,
#endif
};

static __always_inline
struct ipv6_nat_entry *snat_v6_lookup(struct ipv6_ct_tuple *tuple)
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

static __always_inline void snat_v6_delete(struct ipv6_ct_tuple *otuple,
					   struct ipv6_ct_tuple *rtuple)
{
	__snat_delete(&SNAT_MAPPING_IPV6, otuple, rtuple);
}

static __always_inline void snat_v6_swap_tuple(struct ipv6_ct_tuple *otuple,
					       struct ipv6_ct_tuple *rtuple)
{
	__builtin_memset(rtuple, 0, sizeof(*rtuple));
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->daddr = otuple->saddr;
	rtuple->saddr = otuple->daddr;
	rtuple->dport = otuple->sport;
	rtuple->sport = otuple->dport;
	rtuple->flags = otuple->flags == NAT_DIR_EGRESS ?
			NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

static __always_inline int snat_v6_reverse_tuple(struct ipv6_ct_tuple *otuple,
						 struct ipv6_ct_tuple *rtuple)
{
	struct ipv6_nat_entry *ostate;

	ostate = snat_v6_lookup(otuple);
	if (ostate) {
		snat_v6_swap_tuple(otuple, rtuple);
		rtuple->daddr = ostate->to_saddr;
		rtuple->dport = ostate->to_sport;
	}

	return ostate ? 0 : -1;
}

static __always_inline void snat_v6_ct_canonicalize(struct ipv6_ct_tuple *otuple)
{
	union v6addr addr = {};

	otuple->flags = NAT_DIR_EGRESS;
	/* Workaround #5848. */
	ipv6_addr_copy(&addr, &otuple->saddr);
	ipv6_addr_copy(&otuple->saddr, &otuple->daddr);
	ipv6_addr_copy(&otuple->daddr, &addr);
}

static __always_inline void snat_v6_delete_tuples(struct ipv6_ct_tuple *otuple)
{
	struct ipv6_ct_tuple rtuple;

	if (otuple->flags & TUPLE_F_IN)
		return;
	snat_v6_ct_canonicalize(otuple);
	if (!snat_v6_reverse_tuple(otuple, &rtuple))
		snat_v6_delete(otuple, &rtuple);
}

static __always_inline int snat_v6_new_mapping(struct __sk_buff *skb,
					       struct ipv6_ct_tuple *otuple,
					       struct ipv6_nat_entry *ostate,
					       const struct ipv6_nat_target *target)
{
	bool initial_port_in_range = !target->force_range;
	struct ipv6_nat_entry rstate;
	struct ipv6_ct_tuple rtuple;
	int ret, retries;
	__be16 port;

	__builtin_memset(&rstate, 0, sizeof(rstate));
	__builtin_memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;
	ostate->to_sport = otuple->sport;

	snat_v6_swap_tuple(otuple, &rtuple);
	rtuple.daddr = target->addr;

	if (!ipv6_addrcmp(&otuple->saddr, &rtuple.daddr)) {
		ostate->common.host_local = 1;
		rstate.common.host_local = ostate->common.host_local;
	}

	port = bpf_ntohs(rtuple.dport);
	if (target->force_range &&
	    port >= target->min_port && port <= target->max_port)
		initial_port_in_range = true;
#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		if (retries == 0 && !initial_port_in_range)
			goto select_port;
		if (!snat_v6_lookup(&rtuple)) {
			ostate->common.created = bpf_ktime_get_nsec();
			rstate.common.created = ostate->common.created;

			ret = snat_v6_update(otuple, ostate, &rtuple, &rstate);
			if (!ret)
				return 0;
		}
select_port:
		if (NAT_MAP_TYPE == BPF_MAP_TYPE_LRU_HASH &&
		    retries < SNAT_DETERMINISTIC_RETRIES)
			port = __snat_hash(rtuple.dport);
		else
			port = get_prandom_u32();
		port = __snat_clamp_port_range(target->min_port,
					       target->max_port, port);
		rtuple.dport = ostate->to_sport = bpf_htons(port);
	}

	return DROP_NAT_NO_MAPPING;
}

static __always_inline int snat_v6_track_local(struct __sk_buff *skb,
					       struct ipv6_ct_tuple *tuple,
					       struct ipv6_nat_entry *state,
					       int dir, __u32 off,
					       const struct ipv6_nat_target *target)
{
	struct ct_state ct_state;
	struct ipv6_ct_tuple tmp;
	bool needs_ct = false;
	__u32 monitor = 0;
	int ret, where;

	if (state && state->common.host_local) {
		needs_ct = true;
	} else if (!state && dir == NAT_DIR_EGRESS) {
		if (!ipv6_addrcmp(&tuple->saddr, (void *)&target->addr))
			needs_ct = true;
	}
	if (!needs_ct)
		return 0;

	__builtin_memset(&ct_state, 0, sizeof(ct_state));
	__builtin_memcpy(&tmp, tuple, sizeof(tmp));

	where = dir == NAT_DIR_INGRESS ? CT_INGRESS : CT_EGRESS;

	ret = ct_lookup6(get_ct_map6(&tmp), &tmp, skb, off, where,
			 &ct_state, &monitor);
	if (ret < 0) {
		return ret;
	} else if (ret == CT_NEW) {
		ret = ct_create6(get_ct_map6(&tmp), &tmp, skb, where,
				 &ct_state, false);
		if (IS_ERR(ret))
			return ret;
	}

	return 0;
}

static __always_inline int snat_v6_handle_mapping(struct __sk_buff *skb,
						  struct ipv6_ct_tuple *tuple,
						  struct ipv6_nat_entry **state,
						  struct ipv6_nat_entry *tmp,
						  int dir, __u32 off,
						  const struct ipv6_nat_target *target)
{
	int ret;

	*state = snat_v6_lookup(tuple);
	ret = snat_v6_track_local(skb, tuple, *state, dir, off, target);
	if (ret < 0)
		return ret;
	else if (*state)
		return NAT_CONTINUE_XLATE;
	else if (dir == NAT_DIR_INGRESS)
		return tuple->nexthdr != IPPROTO_ICMPV6 &&
		       bpf_ntohs(tuple->dport) < target->min_port ?
		       NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;
	else
		return snat_v6_new_mapping(skb, tuple, (*state = tmp), target);
}

static __always_inline int snat_v6_rewrite_egress(struct __sk_buff *skb,
						  struct ipv6_ct_tuple *tuple,
						  struct ipv6_nat_entry *state,
						  __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum;
	int ret;

	if (!ipv6_addrcmp(&state->to_saddr, &tuple->saddr) &&
	    state->to_sport == tuple->sport)
		return 0;
	sum = csum_diff(&tuple->saddr, 16, &state->to_saddr, 16, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_sport != tuple->sport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(skb, off, offsetof(struct tcphdr, source),
					     &csum, state->to_sport, tuple->sport);
			if (ret < 0)
				return ret;
			break;
		case IPPROTO_ICMPV6: {
			__be32 from, to;

			if (skb_store_bytes(skb, off +
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
	if (skb_store_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    &state->to_saddr, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	if (csum.offset &&
	    csum_l4_replace(skb, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
                return DROP_CSUM_L4;
	return 0;
}

static __always_inline int snat_v6_rewrite_ingress(struct __sk_buff *skb,
						   struct ipv6_ct_tuple *tuple,
						   struct ipv6_nat_entry *state,
						   __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum;
	int ret;

	if (!ipv6_addrcmp(&state->to_daddr, &tuple->daddr) &&
	    state->to_dport == tuple->dport)
		return 0;
	sum = csum_diff(&tuple->daddr, 16, &state->to_daddr, 16, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_dport != tuple->dport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(skb, off,
					     offsetof(struct tcphdr, dest),
					     &csum, state->to_dport,
					     tuple->dport);
			if (ret < 0)
				return ret;
			break;
		case IPPROTO_ICMPV6: {
			__be32 from, to;

			if (skb_store_bytes(skb, off +
					    offsetof(struct icmp6hdr,
						     icmp6_dataun.u_echo.identifier),
					    &state->to_dport,
					    sizeof(state->to_dport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->dport;
			to = state->to_dport;
			sum = csum_diff(&from, 4, &to, 4, sum);
			break;
		}}
	}
	if (skb_store_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			    &state->to_daddr, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	if (csum.offset &&
	    csum_l4_replace(skb, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
                return DROP_CSUM_L4;
	return 0;
}

static __always_inline bool snat_v6_can_skip(const struct ipv6_nat_target *target,
					     const struct ipv6_ct_tuple *tuple, int dir)
{
	__u16 dport = bpf_ntohs(tuple->dport), sport = bpf_ntohs(tuple->sport);

	if (dir == NAT_DIR_EGRESS && sport < NAT_MIN_EGRESS)
		return true;
	if (dir == NAT_DIR_INGRESS && (dport < target->min_port || dport > target->max_port))
		return true;
	return false;
}

static __always_inline int snat_v6_process(struct __sk_buff *skb, int dir,
					   const struct ipv6_nat_target *target)
{
	struct ipv6_nat_entry *state, tmp;
	struct ipv6_ct_tuple tuple = {};
	struct icmp6hdr icmp6hdr;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, hdrlen;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u8 nexthdr;
	__u32 off;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(skb, ETH_HLEN, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	tuple.nexthdr = nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);
	tuple.flags = dir;
	off = ((void *)ip6 - data) + hdrlen;
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (skb_load_bytes(skb, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		break;
	case IPPROTO_ICMPV6:
		if (skb_load_bytes(skb, off, &icmp6hdr, sizeof(icmp6hdr)) < 0)
			return DROP_INVALID;
		/* Letting neighbor solicitation / advertisement pass through. */
		if (icmp6hdr.icmp6_type == 135 || icmp6hdr.icmp6_type == 136)
			return TC_ACT_OK;
		if (icmp6hdr.icmp6_type != ICMPV6_ECHO_REQUEST &&
		    icmp6hdr.icmp6_type != ICMPV6_ECHO_REPLY)
			return DROP_NAT_UNSUPP_PROTO;
		if (dir == NAT_DIR_EGRESS) {
			tuple.dport = 0;
			tuple.sport = icmp6hdr.icmp6_dataun.u_echo.identifier;
		} else {
			tuple.dport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			tuple.sport = 0;
		}
		break;
	default:
		return DROP_NAT_UNSUPP_PROTO;
	};

	if (target->force_range && snat_v6_can_skip(target, &tuple, dir))
		return TC_ACT_OK;
	ret = snat_v6_handle_mapping(skb, &tuple, &state, &tmp, dir, off, target);
	if (ret > 0)
		return TC_ACT_OK;
	if (ret < 0)
		return ret;

	return dir == NAT_DIR_EGRESS ?
	       snat_v6_rewrite_egress(skb, &tuple, state, off) :
	       snat_v6_rewrite_ingress(skb, &tuple, state, off);
}
#else
static __always_inline int snat_v6_process(struct __sk_buff *skb, int dir,
					   const struct ipv6_nat_target *target)
{
	return TC_ACT_OK;
}

static __always_inline void snat_v6_delete_tuples(struct ipv6_ct_tuple *tuple)
{
}
#endif

#ifdef CONNTRACK
static __always_inline void ct_delete4(void *map, struct ipv4_ct_tuple *tuple,
				       struct __sk_buff *skb)
{
	int err;

	if ((err = map_delete_elem(map, tuple)) < 0)
		cilium_dbg(skb, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
	else
		snat_v4_delete_tuples(tuple);
}

static __always_inline void ct_delete6(void *map, struct ipv6_ct_tuple *tuple,
				       struct __sk_buff *skb)
{
	int err;

	if ((err = map_delete_elem(map, tuple)) < 0)
		cilium_dbg(skb, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
	else
		snat_v6_delete_tuples(tuple);
}
#else
static __always_inline void ct_delete4(void *map, struct ipv4_ct_tuple *tuple,
				       struct __sk_buff *skb)
{
}

static __always_inline void ct_delete6(void *map, struct ipv6_ct_tuple *tuple,
				       struct __sk_buff *skb)
{
}
#endif

static __always_inline int snat_process(struct __sk_buff *skb, int dir)
{
	int ret = TC_ACT_OK;

#ifdef ENABLE_MASQUERADE
	switch (skb->protocol) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		struct ipv4_nat_target target = {
			.min_port = SNAT_MAPPING_MIN_PORT,
			.max_port = SNAT_MAPPING_MAX_PORT,
			.addr  = SNAT_IPV4_EXTERNAL,
		};
		ret = snat_v4_process(skb, dir, &target);
		break; }
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		struct ipv6_nat_target target = {
			.min_port = SNAT_MAPPING_MIN_PORT,
			.max_port = SNAT_MAPPING_MAX_PORT,
		};
		BPF_V6(target.addr, SNAT_IPV6_EXTERNAL);
		ret = snat_v6_process(skb, dir, &target);
		break; }
#endif
	}
	if (IS_ERR(ret))
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, dir);
#endif
	return ret;
}
#endif /* __LIB_NAT__ */
