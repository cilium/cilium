/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Simple NAT engine in BPF. */
#pragma once

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
#include "eps.h"
#include "icmp6.h"
#include "nat_46x64.h"
#include "stubs.h"
#include "trace.h"

DECLARE_CONFIG(union v4addr, nat_ipv4_masquerade, "Masquerade address for IPv4 traffic")
DECLARE_CONFIG(union v6addr, nat_ipv6_masquerade, "Masquerade address for IPv6 traffic")

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

#define SNAT_SIGNAL_THRES		(SNAT_COLLISION_RETRIES / 2)

#define snat_v4_needs_masquerade_hook(ctx, target) 0

/* Clamp a port to the range [start, end].
 *
 * Introduces a slight bias.
 *
 * Adapted from "Integer Multiplication (Biased)" in https://www.pcg-random.org/posts/bounded-rands.html
 */
static __always_inline __u16 __snat_clamp_port_range(__u16 start, __u16 end,
						     __u16 val)
{
	/* Account for closed interval. */
	__u32 n = (__u32)(end - start) + 1;
	__u32 m = (__u32)(val) * n;

	return start + (m >> 16);
}

/* Retain a port if it is in range [start, end], otherwise generate a random one.
 *
 * The randomly generated port will have a slight bias.
 */
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
__snat_create(const void *map, const void *tuple, const void *state)
{
	return map_update_elem(map, tuple, state, BPF_NOEXIST);
}

static __always_inline __maybe_unused int
__snat_delete(const void *map, const void *tuple)
{
	return map_delete_elem(map, tuple);
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
	__u16 min_port; /* host endianness */
	__u16 max_port; /* host endianness */
	bool from_local_endpoint;
	bool egress_gateway; /* NAT is needed because of an egress gateway policy */
	__u32 cluster_id;
	bool needs_ct;
	__u32 ifindex; /* Obtained from EGW policy */
};

#if defined(ENABLE_IPV4) && defined(ENABLE_NODEPORT)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ipv4_nat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SNAT_MAPPING_IPV4_SIZE);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_snat_v4_external __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SNAT_COLLISION_RETRIES + 1);
} cilium_snat_v4_alloc_retries __section_maps_btf;

#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
struct per_cluster_snat_mapping_ipv4_inner_map {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ipv4_nat_entry);
	__uint(max_entries, SNAT_MAPPING_IPV4_SIZE);
	__uint(map_flags, LRU_MEM_FLAVOR);
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
} cilium_per_cluster_snat_v4_external __section_maps_btf;
#else
} cilium_per_cluster_snat_v4_external __section_maps_btf = {
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
} cilium_ipmasq_v4 __section_maps_btf;
#endif

static __always_inline void *
get_cluster_snat_map_v4(__u32 cluster_id __maybe_unused)
{
#if defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && defined(ENABLE_INTER_CLUSTER_SNAT)
	if (cluster_id != 0 && cluster_id != CLUSTER_ID)
		return map_lookup_elem(&cilium_per_cluster_snat_v4_external, &cluster_id);
#endif
	return &cilium_snat_v4_external;
}

static __always_inline
struct ipv4_nat_entry *snat_v4_lookup(const struct ipv4_ct_tuple *tuple)
{
	return __snat_lookup(&cilium_snat_v4_external, tuple);
}

static __always_inline void
set_v4_rtuple(const struct ipv4_ct_tuple *otuple,
	      const struct ipv4_nat_entry *ostate,
	      struct ipv4_ct_tuple *rtuple)
{
	rtuple->flags = TUPLE_F_IN;
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->saddr = otuple->daddr;
	rtuple->daddr = ostate->to_saddr;
	rtuple->sport = otuple->dport;
	rtuple->dport = ostate->to_sport;
}

static __always_inline int snat_v4_new_mapping(struct __ctx_buff *ctx, void *map,
					       struct ipv4_ct_tuple *otuple,
					       struct ipv4_nat_entry *ostate,
					       const struct ipv4_nat_target *target,
					       bool needs_ct, __s8 *ext_err)
{
	struct ipv4_ct_tuple rtuple = {};
	struct ipv4_nat_entry rstate;
	__u32 *retries_hist;
	__u32 retries;
	int ret;
	__u16 port;

	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;
	/* .to_sport is selected below */

	/* This tuple matches reply traffic for the SNATed connection: */
	set_v4_rtuple(otuple, ostate, &rtuple);
	/* .dport is selected below */

	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	ostate->common.needs_ct = needs_ct;
	rstate.common.needs_ct = needs_ct;
	rstate.common.created = bpf_mono_now();

#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		rtuple.dport = bpf_htons(port);

		/* Try to create a RevSNAT entry. */
		if (__snat_create(map, &rtuple, &rstate) == 0)
			goto create_nat_entry;

		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
	}

	retries_hist = map_lookup_elem(&cilium_snat_v4_alloc_retries, &(__u32){retries});
	if (retries_hist)
		++*retries_hist;

	/* Loop completed without finding a free port: */
	ret = DROP_NAT_NO_MAPPING;
	goto out;

create_nat_entry:
	retries_hist = map_lookup_elem(&cilium_snat_v4_alloc_retries, &(__u32){retries});
	if (retries_hist)
		++*retries_hist;

	ostate->to_sport = rtuple.dport;
	ostate->common.created = rstate.common.created;

	/* Create the SNAT entry. We just created the RevSNAT entry. */
	ret = __snat_create(map, otuple, ostate);
	if (ret < 0) {
		map_delete_elem(map, &rtuple); /* rollback */
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
			   fraginfo_t fraginfo,
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
		int ret;

		memcpy(&tuple_snat, tuple, sizeof(tuple_snat));
		/* Lookup with SCOPE_FORWARD. Ports are already in correct layout: */
		ipv4_ct_tuple_swap_addrs(&tuple_snat);

		ret = ct_lazy_lookup4(get_ct_map4(&tuple_snat), &tuple_snat, ctx,
				      fraginfo, off, CT_EGRESS, SCOPE_FORWARD,
				      CT_ENTRY_ANY, NULL, &trace->monitor);
		if (ret < 0)
			return ret;

		trace->reason = (enum trace_reason)ret;
		if (ret == CT_NEW) {
			ret = ct_create4(get_ct_map4(&tuple_snat), NULL,
					 &tuple_snat, ctx, CT_EGRESS,
					 NULL, ext_err);
			if (IS_ERR(ret))
				return ret;
		}
	}

	if (*state) {
		int ret;
		struct ipv4_ct_tuple rtuple = {};

		set_v4_rtuple(tuple, *state, &rtuple);
		if (target->addr == (*state)->to_saddr &&
		    needs_ct == (*state)->common.needs_ct) {
			/* Check for the reverse SNAT entry. If it is missing (e.g. due to LRU
			 * eviction), it must be restored before returning.
			 */
			struct ipv4_nat_entry rstate;
			struct ipv4_nat_entry *lookup_result;

			lookup_result = __snat_lookup(map, &rtuple);
			if (!lookup_result) {
				memset(&rstate, 0, sizeof(rstate));
				rstate.to_daddr = tuple->saddr;
				rstate.to_dport = tuple->sport;
				rstate.common.needs_ct = needs_ct;
				rstate.common.created = bpf_mono_now();
				ret = __snat_create(map, &rtuple, &rstate);
				if (ret < 0) {
					if (ext_err)
						*ext_err = (__s8)ret;
					return DROP_NAT_NO_MAPPING;
				}
			}
			barrier_data(*state);
			return 0;
		}

		/* Recreate the SNAT and RevSNAT entries if the source IP is stale.
		 * Otherwise, the packet will be erroneously SNATed with the stale
		 * source IP.
		 */
		ret = __snat_delete(map, tuple);
		if (IS_ERR(ret))
			return ret;

		*state = __snat_lookup(map, &rtuple);
		if (*state)
			/* snat_v4_new_mapping will create new RevSNAT entry even if deleting
			 * the old RevSNAT entry fails. We would leave it behind though.
			 */
			__snat_delete(map, &rtuple);
	}

	*state = tmp;
	return snat_v4_new_mapping(ctx, map, tuple, tmp, target, needs_ct, ext_err);
}

static __always_inline int
snat_v4_rev_nat_handle_mapping(struct __ctx_buff *ctx,
			       struct ipv4_ct_tuple *tuple,
			       fraginfo_t fraginfo,
			       struct ipv4_nat_entry **state,
			       __u32 off,
			       const struct ipv4_nat_target *target,
			       struct trace_ctx *trace)
{
	void *map;

	map = get_cluster_snat_map_v4(target->cluster_id);
	if (!map)
		return DROP_SNAT_NO_MAP_FOUND;

	*state = __snat_lookup(map, tuple);

	if (*state) {
		struct ipv4_nat_entry *lookup_result;
		struct ipv4_nat_entry ostate;
		struct ipv4_ct_tuple otuple = {};
		int ret;

		/* Check for the original SNAT entry. If it is missing (e.g. due to LRU
		 * eviction), it must be restored before returning.
		 */
		otuple.saddr = (*state)->to_daddr;
		otuple.sport = (*state)->to_dport;
		otuple.daddr = tuple->saddr;
		otuple.dport = tuple->sport;
		otuple.nexthdr = tuple->nexthdr;
		otuple.flags = TUPLE_F_OUT;

		lookup_result = __snat_lookup(map, &otuple);
		if (!lookup_result) {
			memset(&ostate, 0, sizeof(ostate));
			ostate.to_saddr = tuple->daddr;
			ostate.to_sport = tuple->dport;
			ostate.common.needs_ct = (*state)->common.needs_ct;
			ostate.common.created = bpf_mono_now();

			ret = __snat_create(map, &otuple, &ostate);
			if (ret < 0)
				return DROP_NAT_NO_MAPPING;
		}
	}

	if (*state && (*state)->common.needs_ct) {
		struct ipv4_ct_tuple tuple_revsnat;
		int ret;

		memcpy(&tuple_revsnat, tuple, sizeof(tuple_revsnat));
		tuple_revsnat.daddr = (*state)->to_daddr;
		tuple_revsnat.dport = (*state)->to_dport;

		/* CT expects a tuple with the source and destination ports reversed,
		 * while NAT uses normal tuples that match packet headers.
		 */
		ipv4_ct_tuple_swap_ports(&tuple_revsnat);

		ret = ct_lazy_lookup4(get_ct_map4(&tuple_revsnat), &tuple_revsnat, ctx,
				      fraginfo, off, CT_INGRESS, SCOPE_REVERSE,
				      CT_ENTRY_ANY, NULL, &trace->monitor);
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

	ret = map_update_elem(&cilium_snat_v4_external, &tmp, &state, 0);
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
			 struct iphdr *ip4 __maybe_unused,
			 fraginfo_t fraginfo __maybe_unused,
			 int l4_off __maybe_unused,
			 struct ipv4_nat_target *target __maybe_unused)
{
	struct endpoint_info *local_ep __maybe_unused;
	struct remote_endpoint_info *remote_ep __maybe_unused;
	int ret;

	ret = snat_v4_needs_masquerade_hook(ctx, target);
	if (IS_ERR(ret))
		return ret;
	if (ret)
		return NAT_NEEDED;

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
	/* To prevent aliasing with masqueraded connections,
	 * we need to track all host connections that use config
	 * nat_ipv4_masquerade.
	 *
	 * This either reserves the source port (so that it's not used
	 * for masquerading), or port-SNATs the host connection (if the sport
	 * is already in use for a masqueraded connection).
	 */
	if (tuple->saddr == CONFIG(nat_ipv4_masquerade).be32) {
		target->addr = CONFIG(nat_ipv4_masquerade).be32;
		target->needs_ct = true;

		return NAT_NEEDED;
	}

	local_ep = __lookup_ip4_endpoint(tuple->saddr);

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

		err = ct_extract_ports4(ctx, ip4, fraginfo, l4_off,
					CT_EGRESS, tuple);
		switch (err) {
		case 0:
			/* If the packet is a reply it means that outside has
			 * initiated the connection, so no need to SNAT the
			 * reply.
			 */
			if (ct_is_reply4(get_ct_map4(tuple), tuple))
				return NAT_PUNT_TO_STACK;

			/* SNAT code has its own port extraction logic: */
			tuple->dport = 0;
			tuple->sport = 0;

			break;
		case DROP_CT_UNKNOWN_PROTO:
			/* tolerate L4 protocols not supported by CT: */
			break;
		default:
			return err;
		}
	}

	/* Check if the packet matches an egress NAT policy and so needs to be SNAT'ed.
	 *
	 * This check must happen before the IPV4_SNAT_EXCLUSION_DST_CIDR check below as
	 * the destination may be in the SNAT exclusion CIDR but regardless of that we
	 * always want to SNAT a packet if it's matched by an egress NAT policy.
	 */
#if defined(ENABLE_EGRESS_GATEWAY_COMMON)
	if (egress_gw_snat_needed_hook(tuple->saddr, tuple->daddr, &target->addr,
				       &target->ifindex)) {
		if (target->addr == EGRESS_GATEWAY_NO_EGRESS_IP)
			return DROP_NO_EGRESS_IP;

		target->egress_gateway = true;
		/* If the endpoint is local, then the connection is already tracked. */
		if (!local_ep)
			target->needs_ct = true;

		return NAT_NEEDED;
	}
#endif

	/* Do not MASQ if a dst IP belongs to a pods CIDR
	 * (ipv4-native-routing-cidr if specified, otherwise local pod CIDR).
	 */
#ifdef IPV4_SNAT_EXCLUSION_DST_CIDR
	if (ipv4_is_in_subnet(tuple->daddr, IPV4_SNAT_EXCLUSION_DST_CIDR,
			      IPV4_SNAT_EXCLUSION_DST_CIDR_LEN))
		return NAT_PUNT_TO_STACK;
#endif

	/* if this is a localhost endpoint, no SNAT is needed */
	if (local_ep && (local_ep->flags & ENDPOINT_F_HOST))
		return NAT_PUNT_TO_STACK;

	/* Do not SNAT if dst belongs to any ip-masq-agent subnet. */
#ifdef ENABLE_IP_MASQ_AGENT_IPV4
	{
		struct lpm_v4_key pfx;

		pfx.lpm.prefixlen = 32;
		memcpy(pfx.lpm.data, &tuple->daddr, sizeof(pfx.addr));
		if (map_lookup_elem(&cilium_ipmasq_v4, &pfx))
			return NAT_PUNT_TO_STACK;
	}
#endif

	/* Masquerading for pod-to-remote-node traffic depends on the
	 * datapath configuration (native vs overlay routing):
	 */
	remote_ep = lookup_ip4_remote_endpoint(tuple->daddr, 0);
	if (remote_ep && identity_is_remote_node(remote_ep->sec_identity)) {
		/* Don't masquerade in native-routing mode: */
		if (!is_defined(TUNNEL_MODE))
			return NAT_PUNT_TO_STACK;

		/* In overlay routing mode, pod-to-remote-node traffic
		 * typically doesn't get transported via the overlay
		 * network (https://github.com/cilium/cilium/issues/12624).
		 *
		 * Therefore such packet has to be masqueraded.
		 * Otherwise it might be dropped
		 * either by underlying network (e.g. AWS drops
		 * packets by default from unknown subnets) or
		 * by the remote node if its native dev's
		 * rp_filter=1.
		 */

		if (remote_ep->flag_skip_tunnel)
			return NAT_PUNT_TO_STACK;
	}

	if (local_ep) {
		target->addr = CONFIG(nat_ipv4_masquerade).be32;
		return NAT_NEEDED;
	}
#endif /*ENABLE_MASQUERADE_IPV4 && IS_BPF_HOST */

	return NAT_PUNT_TO_STACK;
}

static __always_inline __maybe_unused int
snat_v4_nat_handle_icmp_error(struct __ctx_buff *ctx, __u64 off)
{
	__u32 inner_l3_off = (__u32)(off + sizeof(struct icmphdr));
	struct ipv4_ct_tuple tuple = {};
	struct ipv4_nat_entry *state;
	struct iphdr iphdr;
	__u16 port_off;
	__u32 icmpoff;
	__u8 type;
	int ret;

	/* According to the RFC 5508, any networking equipment that is
	 * responding with an ICMP Error packet should embed the original
	 * packet in its response.
	 */
	if (ctx_load_bytes(ctx, inner_l3_off, &iphdr, sizeof(iphdr)) < 0)
		return DROP_INVALID;
	/* From the embedded IP headers we should be able to determine
	 * corresponding protocol, IP src/dst of the packet sent to resolve
	 * the NAT session.
	 */
	tuple.nexthdr = iphdr.protocol;
	tuple.saddr = iphdr.daddr;
	tuple.daddr = iphdr.saddr;
	tuple.flags = NAT_DIR_EGRESS;

	icmpoff = inner_l3_off + ipv4_hdrlen(&iphdr);
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

		port_off = TCP_DPORT_OFF;
		break;
	case IPPROTO_ICMP:
		if (ctx_load_bytes(ctx, icmpoff, &type, sizeof(type)) < 0)
			return DROP_INVALID;

		switch (type) {
		case ICMP_ECHO:
			return NAT_PUNT_TO_STACK;
		case ICMP_ECHOREPLY:
			port_off = offsetof(struct icmphdr, un.echo.id);
			break;
		default:
			return DROP_UNKNOWN_ICMP4_CODE;
		}

		if (ctx_load_bytes(ctx, icmpoff + port_off,
				   &tuple.sport, sizeof(tuple.sport)) < 0)
			return DROP_INVALID;
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
	ret = snat_v4_rewrite_headers(ctx, tuple.nexthdr, inner_l3_off, true, icmpoff,
				      tuple.saddr, state->to_saddr, IPV4_DADDR_OFF,
				      tuple.sport, state->to_sport, port_off);
	if (IS_ERR(ret))
		return ret;

	/* Rewrite outer headers. No port rewrite needed. */
	return snat_v4_rewrite_headers(ctx, IPPROTO_ICMP, ETH_HLEN, true, (int)off,
				       tuple.saddr, state->to_saddr, IPV4_SADDR_OFF,
				       0, 0, 0);
}

static __always_inline int
__snat_v4_nat(struct __ctx_buff *ctx, struct ipv4_ct_tuple *tuple, fraginfo_t fraginfo,
	      int l4_off, bool update_tuple, const struct ipv4_nat_target *target,
	      __u16 port_off, struct trace_ctx *trace, __s8 *ext_err)
{
	struct ipv4_nat_entry *state, tmp;
	int ret;

	ret = snat_v4_nat_handle_mapping(ctx, tuple, fraginfo, &state, &tmp,
					 l4_off, target, trace, ext_err);
	if (ret < 0)
		return ret;

	ret = snat_v4_rewrite_headers(ctx, tuple->nexthdr, ETH_HLEN,
				      ipfrag_has_l4_header(fraginfo), l4_off,
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
	    struct iphdr *ip4, fraginfo_t fraginfo,
	    int off, struct ipv4_nat_target *target,
	    struct trace_ctx *trace, __s8 *ext_err)
{
	struct icmphdr icmphdr __align_stack_8;
	__u16 port_off;
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	switch (tuple->nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		/* If we don't track fragments, packets without an L4 header
		 * can't be NATed. Even though the first fragment always has an
		 * L4 header, NATing it in this situation is useless, because
		 * the following fragments won't be able to pass the NAT.
		 */
		if (!is_defined(ENABLE_IPV4_FRAGMENTS) && ipfrag_is_fragment(fraginfo))
			return DROP_FRAG_NOSUPPORT;

		ret = ipv4_load_l4_ports(ctx, ip4, fraginfo, off,
					 CT_EGRESS, &tuple->dport);
		if (ret < 0)
			return ret;

		ipv4_ct_tuple_swap_ports(tuple);
		port_off = TCP_SPORT_OFF;

		if (snat_v4_nat_can_skip(target, tuple))
			return NAT_PUNT_TO_STACK;

		break;
	case IPPROTO_ICMP:
		/* Fragmented ECHO packets are not supported currently. Drop all
		 * fragments, because letting the first fragment pass would be
		 * useless anyway.
		 * ICMP error packets are not supposed to be fragmented.
		 */
		if (unlikely(ipfrag_is_fragment(fraginfo)))
			return DROP_INVALID;
		if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;

		switch (icmphdr.type) {
		case ICMP_ECHO:
			tuple->dport = 0;
			tuple->sport = icmphdr.un.echo.id;
			port_off = offsetof(struct icmphdr, un.echo.id);
			/* Don't clamp the ID field: */
			target->min_port = 0;
			target->max_port = UINT16_MAX;

			break;
		case ICMP_ECHOREPLY:
			return NAT_PUNT_TO_STACK;
		case ICMP_DEST_UNREACH:
			if (icmphdr.code > NR_ICMP_UNREACH)
				return DROP_UNKNOWN_ICMP4_CODE;

			goto nat_icmp_v4;
		case ICMP_TIME_EXCEEDED:
			switch (icmphdr.code) {
			case ICMP_EXC_TTL:
			case ICMP_EXC_FRAGTIME:
				break;
			default:
				return DROP_UNKNOWN_ICMP4_CODE;
			}

nat_icmp_v4:
			return snat_v4_nat_handle_icmp_error(ctx, off);
		default:
			return DROP_NAT_UNSUPP_PROTO;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	return __snat_v4_nat(ctx, tuple, fraginfo, off, false, target, port_off, trace, ext_err);
}

static __always_inline __maybe_unused int
snat_v4_rev_nat_handle_icmp_error(struct __ctx_buff *ctx,
				  __u64 inner_l3_off,
				  struct ipv4_nat_entry **state)
{
	struct ipv4_ct_tuple tuple = {};
	struct iphdr iphdr;
	__u16 port_off;
	__u32 icmpoff;
	__u8 type;

	/* According to the RFC 5508, any networking equipment that is
	 * responding with an ICMP Error packet should embed the original
	 * packet in its response.
	 */

	if (ctx_load_bytes(ctx, (__u32)inner_l3_off, &iphdr, sizeof(iphdr)) < 0)
		return DROP_INVALID;

	/* From the embedded IP headers we should be able to determine
	 * corresponding protocol, IP src/dst of the packet sent to resolve the
	 * NAT session.
	 */
	tuple.nexthdr = iphdr.protocol;
	tuple.saddr = iphdr.daddr;
	tuple.daddr = iphdr.saddr;
	tuple.flags = NAT_DIR_INGRESS;

	icmpoff = (__u32)(inner_l3_off + ipv4_hdrlen(&iphdr));
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
		if (ctx_load_bytes(ctx, icmpoff, &type, sizeof(type)) < 0)
			return DROP_INVALID;

		switch (type) {
		case ICMP_ECHO:
			port_off = offsetof(struct icmphdr, un.echo.id);
			break;
		case ICMP_ECHOREPLY:
			return NAT_PUNT_TO_STACK;
		default:
			return DROP_UNKNOWN_ICMP4_CODE;
		}

		if (ctx_load_bytes(ctx, icmpoff + port_off,
				   &tuple.dport, sizeof(tuple.dport)) < 0)
			return DROP_INVALID;
		break;
	default:
		return NAT_PUNT_TO_STACK;
	}

	*state = snat_v4_lookup(&tuple);
	if (!*state)
		return NAT_PUNT_TO_STACK;

	/* The embedded packet was SNATed on egress. Reverse it again: */
	return snat_v4_rewrite_headers(ctx, tuple.nexthdr, (int)inner_l3_off, true, icmpoff,
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
	fraginfo_t fraginfo;
	__u64 off, inner_l3_off;
	__be16 to_dport = 0;
	__u16 port_off = 0;
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	fraginfo = ipfrag_encode_ipv4(ip4);

	snat_v4_init_tuple(ip4, NAT_DIR_INGRESS, &tuple);

	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		ret = ipv4_load_l4_ports(ctx, ip4, fraginfo, (int)off,
					 CT_INGRESS, &tuple.dport);
		if (ret < 0)
			return ret;

		ipv4_ct_tuple_swap_ports(&tuple);
		port_off = TCP_DPORT_OFF;

		if (snat_v4_rev_nat_can_skip(target, &tuple))
			return NAT_PUNT_TO_STACK;

		break;
	case IPPROTO_ICMP:
		/* Fragmented ECHOREPLY packets are not supported currently.
		 * Drop all fragments, because letting the first fragment pass
		 * would be useless anyway.
		 * ICMP error packets are not supposed to be fragmented.
		 */
		if (unlikely(ipfrag_is_fragment(fraginfo)))
			return DROP_INVALID;
		if (ctx_load_bytes(ctx, (__u32)off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;

		switch (icmphdr.type) {
		case ICMP_ECHOREPLY:
			tuple.dport = icmphdr.un.echo.id;
			tuple.sport = 0;
			port_off = offsetof(struct icmphdr, un.echo.id);
			break;
		case ICMP_DEST_UNREACH:
			if (icmphdr.code > NR_ICMP_UNREACH)
				return NAT_PUNT_TO_STACK;

			goto rev_nat_icmp_v4;
		case ICMP_TIME_EXCEEDED:
			switch (icmphdr.code) {
			case ICMP_EXC_TTL:
			case ICMP_EXC_FRAGTIME:
				break;
			default:
				return NAT_PUNT_TO_STACK;
			}

rev_nat_icmp_v4:
			inner_l3_off = off + sizeof(struct icmphdr);

			ret = snat_v4_rev_nat_handle_icmp_error(ctx, inner_l3_off, &state);
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

	ret = snat_v4_rev_nat_handle_mapping(ctx, &tuple, fraginfo, &state,
					     (__u32)off, target, trace);
	if (ret < 0)
		return ret;

	/* Skip port rewrite for ICMP_DEST_UNREACH by passing old_port == new_port == 0. */
	to_dport = state->to_dport;

rewrite:
	return snat_v4_rewrite_headers(ctx, tuple.nexthdr, ETH_HLEN,
				       ipfrag_has_l4_header(fraginfo), (int)off,
				       tuple.daddr, state->to_daddr, IPV4_DADDR_OFF,
				       tuple.dport, to_dport, port_off);
}
#else /* defined(ENABLE_IPV4) && defined(ENABLE_NODEPORT) */
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
#endif /* defined(ENABLE_IPV4) && defined(ENABLE_NODEPORT) */

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
	__u16 min_port; /* host endianness */
	__u16 max_port; /* host endianness */
	bool from_local_endpoint;
	bool needs_ct;
	bool egress_gateway; /* NAT is needed because of an egress gateway policy */
	__u32 ifindex; /* Obtained from EGW policy */
};

#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_ct_tuple);
	__type(value, struct ipv6_nat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SNAT_MAPPING_IPV6_SIZE);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_snat_v6_external __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, SNAT_COLLISION_RETRIES + 1);
} cilium_snat_v6_alloc_retries __section_maps_btf;

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
		__uint(map_flags, LRU_MEM_FLAVOR);
	});
} cilium_per_cluster_snat_v6_external __section_maps_btf;
#endif

#ifdef ENABLE_IP_MASQ_AGENT_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v6_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_ipmasq_v6 __section_maps_btf;
#endif

static __always_inline void *
get_cluster_snat_map_v6(__u32 cluster_id __maybe_unused)
{
#if defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && defined(ENABLE_INTER_CLUSTER_SNAT)
	if (cluster_id != 0 && cluster_id != CLUSTER_ID)
		return map_lookup_elem(&cilium_per_cluster_snat_v6_external, &cluster_id);
#endif
	return &cilium_snat_v6_external;
}

static __always_inline
struct ipv6_nat_entry *snat_v6_lookup(const struct ipv6_ct_tuple *tuple)
{
	return __snat_lookup(&cilium_snat_v6_external, tuple);
}

static __always_inline void
set_v6_rtuple(const struct ipv6_ct_tuple *otuple,
	      const struct ipv6_nat_entry *ostate,
	      struct ipv6_ct_tuple *rtuple)
{
	rtuple->flags = TUPLE_F_IN;
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->saddr = otuple->daddr;
	rtuple->daddr = ostate->to_saddr;
	rtuple->sport = otuple->dport;
	rtuple->dport = ostate->to_sport;
}

static __always_inline int snat_v6_new_mapping(struct __ctx_buff *ctx,
					       struct ipv6_ct_tuple *otuple,
					       struct ipv6_nat_entry *ostate,
					       const struct ipv6_nat_target *target,
					       bool needs_ct, __s8 *ext_err)
{
	struct ipv6_ct_tuple rtuple = {};
	struct ipv6_nat_entry rstate;
	__u32 *retries_hist;
	__u32 retries;
	int ret;
	__u16 port;

	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;
	/* .to_sport is selected below */

	set_v6_rtuple(otuple, ostate, &rtuple);
	/* .dport is selected below */

	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	ostate->common.needs_ct = needs_ct;
	rstate.common.needs_ct = needs_ct;
	rstate.common.created = bpf_mono_now();

#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		rtuple.dport = bpf_htons(port);

		if (__snat_create(&cilium_snat_v6_external, &rtuple, &rstate) == 0)
			goto create_nat_entry;

		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
	}

	retries_hist = map_lookup_elem(&cilium_snat_v6_alloc_retries, &(__u32){retries});
	if (retries_hist)
		++*retries_hist;

	ret = DROP_NAT_NO_MAPPING;
	goto out;

create_nat_entry:
	retries_hist = map_lookup_elem(&cilium_snat_v6_alloc_retries, &(__u32){retries});
	if (retries_hist)
		++*retries_hist;

	ostate->to_sport = rtuple.dport;
	ostate->common.created = rstate.common.created;

	ret = __snat_create(&cilium_snat_v6_external, otuple, ostate);
	if (ret < 0) {
		map_delete_elem(&cilium_snat_v6_external, &rtuple); /* rollback */
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
			   fraginfo_t fraginfo,
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
		int ret;

		memcpy(&tuple_snat, tuple, sizeof(tuple_snat));
		/* Lookup with SCOPE_FORWARD. Ports are already in correct layout: */
		ipv6_ct_tuple_swap_addrs(&tuple_snat);

		ret = ct_lazy_lookup6(get_ct_map6(&tuple_snat), &tuple_snat, ctx,
				      fraginfo, off, CT_EGRESS, SCOPE_FORWARD,
				      CT_ENTRY_ANY, NULL, &trace->monitor);
		if (ret < 0)
			return ret;

		trace->reason = (enum trace_reason)ret;
		if (ret == CT_NEW) {
			ret = ct_create6(get_ct_map6(&tuple_snat), NULL,
					 &tuple_snat, ctx, CT_EGRESS,
					 NULL, ext_err);
			if (IS_ERR(ret))
				return ret;
		}
	}

	if (*state) {
		int ret;
		struct ipv6_ct_tuple rtuple = {};

		set_v6_rtuple(tuple, *state, &rtuple);
		if (ipv6_addr_equals(&target->addr, &(*state)->to_saddr) &&
		    needs_ct == (*state)->common.needs_ct) {
			/* Check for the reverse SNAT entry. If it is missing (e.g. due to LRU
			 * eviction), it must be restored before returning.
			 */
			struct ipv6_nat_entry rstate;
			struct ipv6_nat_entry *lookup_result;

			lookup_result = snat_v6_lookup(&rtuple);
			if (!lookup_result) {
				memset(&rstate, 0, sizeof(rstate));
				rstate.to_daddr = tuple->saddr;
				rstate.to_dport = tuple->sport;
				rstate.common.needs_ct = needs_ct;
				rstate.common.created = bpf_mono_now();
				ret = __snat_create(&cilium_snat_v6_external, &rtuple, &rstate);
				if (ret < 0) {
					if (ext_err)
						*ext_err = (__s8)ret;
					return DROP_NAT_NO_MAPPING;
				}
			}
			barrier_data(*state);
			return 0;
		}

		/* See comment in snat_v4_nat_handle_mapping */
		ret = __snat_delete(&cilium_snat_v6_external, tuple);
		if (IS_ERR(ret))
			return ret;

		*state = snat_v6_lookup(&rtuple);
		if (*state)
			__snat_delete(&cilium_snat_v6_external, &rtuple);
	}

	*state = tmp;
	return snat_v6_new_mapping(ctx, tuple, tmp, target, needs_ct, ext_err);
}

static __always_inline int
snat_v6_rev_nat_handle_mapping(struct __ctx_buff *ctx,
			       struct ipv6_ct_tuple *tuple,
			       fraginfo_t fraginfo,
			       struct ipv6_nat_entry **state,
			       __u32 off,
			       struct trace_ctx *trace)
{
	*state = snat_v6_lookup(tuple);

	if (*state) {
		struct ipv6_nat_entry *lookup_result;
		struct ipv6_nat_entry ostate;
		struct ipv6_ct_tuple otuple = {};
		int ret;

		/* Check for the original SNAT entry. If it is missing (e.g. due to LRU
		 * eviction), it must be restored before returning.
		 */
		otuple.saddr = (*state)->to_daddr;
		otuple.sport = (*state)->to_dport;
		otuple.daddr = tuple->saddr;
		otuple.dport = tuple->sport;
		otuple.nexthdr = tuple->nexthdr;
		otuple.flags = TUPLE_F_OUT;

		lookup_result = snat_v6_lookup(&otuple);
		if (!lookup_result) {
			memset(&ostate, 0, sizeof(ostate));
			ostate.to_saddr = tuple->daddr;
			ostate.to_sport = tuple->dport;
			ostate.common.needs_ct = (*state)->common.needs_ct;
			ostate.common.created = bpf_mono_now();

			ret = __snat_create(&cilium_snat_v6_external, &otuple, &ostate);
			if (ret < 0)
				return DROP_NAT_NO_MAPPING;
		}
	}

	if (*state && (*state)->common.needs_ct) {
		struct ipv6_ct_tuple tuple_revsnat;
		int ret;

		memcpy(&tuple_revsnat, tuple, sizeof(tuple_revsnat));
		ipv6_addr_copy(&tuple_revsnat.daddr, &(*state)->to_daddr);
		tuple_revsnat.dport = (*state)->to_dport;

		/* CT expects a tuple with the source and destination ports reversed,
		 * while NAT uses normal tuples that match packet headers.
		 */
		ipv6_ct_tuple_swap_ports(&tuple_revsnat);

		ret = ct_lazy_lookup6(get_ct_map6(&tuple_revsnat), &tuple_revsnat, ctx,
				      fraginfo, off, CT_INGRESS, SCOPE_REVERSE,
				      CT_ENTRY_ANY, NULL, &trace->monitor);
		if (ret < 0)
			return ret;

		trace->reason = (enum trace_reason)ret;
	}

	if (*state)
		return 0;

	return DROP_NAT_NO_MAPPING;
}

static __always_inline int
snat_v6_rewrite_headers(struct __ctx_buff *ctx, __u8 nexthdr, int l3_off,
			bool has_l4_header, int l4_off,
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

	if (!has_l4_header)
		return 0;

	csum_l4_offset_and_flags(nexthdr, &csum);

	if (old_port != new_port) {
		int err;

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

		/* Amend the L4 checksum due to changing the ports. */
		err = l4_modify_port(ctx, l4_off, port_off, &csum, new_port, old_port);
		if (err < 0)
			return err;
	}

	if (csum.offset &&
	    csum_l4_replace(ctx, l4_off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}

static __always_inline bool
snat_v6_nat_can_skip(const struct ipv6_nat_target *target,
		     const struct ipv6_ct_tuple *tuple)
{
	__u16 sport = bpf_ntohs(tuple->sport);

#if defined(ENABLE_EGRESS_GATEWAY_COMMON) && defined(IS_BPF_HOST)
	if (target->egress_gateway)
		return false;
#endif

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

	ret = map_update_elem(&cilium_snat_v6_external, &tmp, &state, 0);
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
			 struct ipv6hdr *ip6 __maybe_unused,
			 fraginfo_t fraginfo __maybe_unused,
			 int l4_off __maybe_unused,
			 struct ipv6_nat_target *target __maybe_unused)
{
	union v6addr masq_addr __maybe_unused = CONFIG(nat_ipv6_masquerade);
	struct remote_endpoint_info *remote_ep __maybe_unused;
	struct endpoint_info *local_ep __maybe_unused;

	/* See comments in snat_v4_needs_masquerade(). */
#if defined(ENABLE_MASQUERADE_IPV6) && defined(IS_BPF_HOST)
	if (ipv6_addr_equals(&tuple->saddr, &masq_addr)) {
		ipv6_addr_copy(&target->addr, &masq_addr);
		target->needs_ct = true;

		return NAT_NEEDED;
	}

	local_ep = __lookup_ip6_endpoint(&tuple->saddr);

	if (local_ep) {
		int err;

		target->from_local_endpoint = true;

		err = ct_extract_ports6(ctx, ip6, fraginfo, l4_off,
					CT_EGRESS, tuple);
		switch (err) {
		case 0:
			if (ct_is_reply6(get_ct_map6(tuple), tuple))
				return NAT_PUNT_TO_STACK;

			/* SNAT code has its own port extraction logic: */
			tuple->dport = 0;
			tuple->sport = 0;

			break;
		case DROP_CT_UNKNOWN_PROTO:
			/* tolerate L4 protocols not supported by CT: */
			break;
		default:
			return err;
		}
	}

/* Check if the packet matches an egress NAT policy and so needs to be SNAT'ed. */
#if defined(ENABLE_EGRESS_GATEWAY_COMMON)
	if (egress_gw_snat_needed_hook_v6(&tuple->saddr, &tuple->daddr, &target->addr,
					  &target->ifindex)) {
		if (ipv6_addr_equals(&target->addr, &EGRESS_GATEWAY_NO_EGRESS_IP_V6))
			return DROP_NO_EGRESS_IP;

		target->egress_gateway = true;
		/* If the endpoint is local, then the connection is already tracked. */
		if (!local_ep)
			target->needs_ct = true;

		return NAT_NEEDED;
	}
#endif

# ifdef IPV6_SNAT_EXCLUSION_DST_CIDR
	{
		union v6addr excl_cidr_mask = IPV6_SNAT_EXCLUSION_DST_CIDR_MASK;
		union v6addr excl_cidr = IPV6_SNAT_EXCLUSION_DST_CIDR;

		if (ipv6_addr_in_net(&tuple->daddr, &excl_cidr, &excl_cidr_mask))
			return NAT_PUNT_TO_STACK;
	}
# endif /* IPV6_SNAT_EXCLUSION_DST_CIDR */

	if (local_ep && (local_ep->flags & ENDPOINT_F_HOST))
		return NAT_PUNT_TO_STACK;

#ifdef ENABLE_IP_MASQ_AGENT_IPV6
	{
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
		if (map_lookup_elem(&cilium_ipmasq_v6, &pfx))
			return NAT_PUNT_TO_STACK;
	}
#endif

	remote_ep = lookup_ip6_remote_endpoint(&tuple->daddr, 0);
	if (remote_ep && identity_is_remote_node(remote_ep->sec_identity)) {
		if (!is_defined(TUNNEL_MODE))
			return NAT_PUNT_TO_STACK;

		if (remote_ep->flag_skip_tunnel)
			return NAT_PUNT_TO_STACK;
	}

	if (local_ep) {
		ipv6_addr_copy(&target->addr, &masq_addr);
		return NAT_NEEDED;
	}
#endif /* ENABLE_MASQUERADE_IPV6 && IS_BPF_HOST */

	return NAT_PUNT_TO_STACK;
}

static __always_inline __maybe_unused int
snat_v6_nat_handle_icmp_error(struct __ctx_buff *ctx, __u64 off, bool has_l4_header)
{
	__u32 inner_l3_off = (__u32)(off + sizeof(struct icmp6hdr));
	struct ipv6_ct_tuple tuple = {};
	struct ipv6_nat_entry *state;
	struct ipv6hdr ip6;
	fraginfo_t fraginfo;
	__u16 port_off;
	__u32 icmpoff;
	int hdrlen;
	__u8 type;
	int ret;

	/* According to the RFC 5508, any networking equipment that is
	 * responding with an ICMP Error packet should embed the original
	 * packet in its response.
	 */
	if (ctx_load_bytes(ctx, inner_l3_off, &ip6, sizeof(ip6)) < 0)
		return DROP_INVALID;

	/* From the embedded IP headers we should be able to determine
	 * corresponding protocol, IP src/dst of the packet sent to resolve
	 * the NAT session.
	 */
	tuple.nexthdr = ip6.nexthdr;
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6.daddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6.saddr);
	tuple.flags = NAT_DIR_EGRESS;

	hdrlen = ipv6_hdrlen_offset(ctx, inner_l3_off, &tuple.nexthdr, &fraginfo);
	if (hdrlen < 0)
		return hdrlen;

	icmpoff = inner_l3_off + hdrlen;

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

		port_off = TCP_DPORT_OFF;
		break;
	case IPPROTO_ICMPV6:
		if (icmp6_load_type(ctx, icmpoff, &type) < 0)
			return DROP_INVALID;

		switch (type) {
		case ICMPV6_ECHO_REQUEST:
			return NAT_PUNT_TO_STACK;
		case ICMPV6_ECHO_REPLY:
			port_off = offsetof(struct icmp6hdr, icmp6_dataun.u_echo.identifier);
			break;
		default:
			return DROP_UNKNOWN_ICMP6_CODE;
		}

		if (ctx_load_bytes(ctx, icmpoff + port_off,
				   &tuple.sport, sizeof(tuple.sport)) < 0)
			return DROP_INVALID;
		break;
	default:
		return DROP_UNKNOWN_L4;
	}
	state = snat_v6_lookup(&tuple);
	if (!state)
		return NAT_PUNT_TO_STACK;

	/* We found SNAT entry to NAT embedded packet. The destination addr
	 * should be NATed according to the entry.
	 */
	ret = snat_v6_rewrite_headers(ctx, tuple.nexthdr, inner_l3_off, true, icmpoff,
				      &tuple.saddr, &state->to_saddr, IPV6_DADDR_OFF,
				      tuple.sport, state->to_sport, port_off);
	if (IS_ERR(ret))
		return ret;

	/* Rewrite outer headers. No port rewrite needed. */
	return snat_v6_rewrite_headers(ctx, IPPROTO_ICMPV6, ETH_HLEN, has_l4_header, (int)off,
				       &tuple.saddr, &state->to_saddr, IPV6_SADDR_OFF,
				       0, 0, 0);
}

static __always_inline int
__snat_v6_nat(struct __ctx_buff *ctx, struct ipv6_ct_tuple *tuple, fraginfo_t fraginfo,
	      int l4_off, bool update_tuple, const struct ipv6_nat_target *target,
	      __u16 port_off, struct trace_ctx *trace, __s8 *ext_err)
{
	struct ipv6_nat_entry *state, tmp;
	int ret;

	ret = snat_v6_nat_handle_mapping(ctx, tuple, fraginfo, &state, &tmp,
					 l4_off, target, trace, ext_err);
	if (ret < 0)
		return ret;

	ret = snat_v6_rewrite_headers(ctx, tuple->nexthdr, ETH_HLEN,
				      ipfrag_has_l4_header(fraginfo), l4_off,
				      &tuple->saddr, &state->to_saddr, IPV6_SADDR_OFF,
				      tuple->sport, state->to_sport, port_off);

	if (update_tuple) {
		ipv6_addr_copy(&tuple->saddr, &state->to_saddr);
		tuple->sport = state->to_sport;
	}

	return ret;
}

static __always_inline __maybe_unused int
snat_v6_nat(struct __ctx_buff *ctx, struct ipv6_ct_tuple *tuple,
	    struct ipv6hdr *ip6, fraginfo_t fraginfo,
	    int off, struct ipv6_nat_target *target,
	    struct trace_ctx *trace, __s8 *ext_err)
{
	struct icmp6hdr icmp6hdr __align_stack_8;
	__u16 port_off;
	int ret;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	switch (tuple->nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		/* If we don't track fragments, packets without an L4 header
		 * can't be NATed. Even though the first fragment always has an
		 * L4 header, NATing it in this situation is useless, because
		 * the following fragments won't be able to pass the NAT.
		 */
		if (!is_defined(ENABLE_IPV6_FRAGMENTS) && ipfrag_is_fragment(fraginfo))
			return DROP_FRAG_NOSUPPORT;

		ret = ipv6_load_l4_ports(ctx, ip6, fraginfo, off,
					 CT_EGRESS, &tuple->dport);
		if (ret < 0)
			return ret;

		ipv6_ct_tuple_swap_ports(tuple);
		port_off = TCP_SPORT_OFF;

		if (snat_v6_nat_can_skip(target, tuple))
			return NAT_PUNT_TO_STACK;

		break;
	case IPPROTO_ICMPV6:
		if (ipfrag_is_fragment(fraginfo))
			return DROP_INVALID;
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
			/* Don't clamp the ID field: */
			target->min_port = 0;
			target->max_port = UINT16_MAX;

			break;
		case ICMPV6_DEST_UNREACH:
			if (icmp6hdr.icmp6_code > ICMPV6_REJECT_ROUTE)
				return DROP_UNKNOWN_ICMP6_CODE;

			goto nat_icmp_v6;
		case ICMPV6_PKT_TOOBIG:
			goto nat_icmp_v6;
		case ICMPV6_TIME_EXCEED:
			switch (icmp6hdr.icmp6_code) {
			case ICMPV6_EXC_HOPLIMIT:
			case ICMPV6_EXC_FRAGTIME:
				break;
			default:
				return DROP_UNKNOWN_ICMP6_CODE;
			}

nat_icmp_v6:
			return snat_v6_nat_handle_icmp_error(ctx, off, true);
		default:
			return DROP_NAT_UNSUPP_PROTO;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	return __snat_v6_nat(ctx, tuple, fraginfo, off, false, target, port_off, trace, ext_err);
}

static __always_inline __maybe_unused int
snat_v6_rev_nat_handle_icmp_pkt_toobig(struct __ctx_buff *ctx,
				       __u32 inner_l3_off,
				       struct ipv6_nat_entry **state)
{
	struct ipv6_ct_tuple tuple = {};
	struct ipv6hdr iphdr;
	fraginfo_t fraginfo;
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

	hdrlen = ipv6_hdrlen_offset(ctx, inner_l3_off, &tuple.nexthdr, &fraginfo);
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
				   &tuple.dport, sizeof(tuple.dport)) < 0)
			return DROP_INVALID;
		break;
	default:
		return NAT_PUNT_TO_STACK;
	}

	*state = snat_v6_lookup(&tuple);
	if (!*state)
		return NAT_PUNT_TO_STACK;

	/* The embedded packet was SNATed on egress. Reverse it again: */
	return snat_v6_rewrite_headers(ctx, tuple.nexthdr, inner_l3_off, true, icmpoff,
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
	fraginfo_t fraginfo;
	__be16 to_dport = 0;
	__u16 port_off = 0;
	int ret, hdrlen;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen_with_fraginfo(ctx, &tuple.nexthdr, &fraginfo);
	if (hdrlen < 0)
		return hdrlen;

	snat_v6_init_tuple(ip6, NAT_DIR_INGRESS, &tuple);

	off = (__u32)(((void *)ip6 - data) + hdrlen);
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		ret = ipv6_load_l4_ports(ctx, ip6, fraginfo, (int)off,
					 CT_INGRESS, &tuple.dport);
		if (ret < 0)
			return ret;

		ipv6_ct_tuple_swap_ports(&tuple);
		port_off = TCP_DPORT_OFF;

		if (snat_v6_rev_nat_can_skip(target, &tuple))
			return NAT_PUNT_TO_STACK;

		break;
	case IPPROTO_ICMPV6:
		if (ipfrag_is_fragment(fraginfo))
			return DROP_INVALID;
		if (ctx_load_bytes(ctx, off, &icmp6hdr, sizeof(icmp6hdr)) < 0)
			return DROP_INVALID;

		switch (icmp6hdr.icmp6_type) {
		case ICMPV6_ECHO_REPLY:
			tuple.dport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			tuple.sport = 0;
			port_off = offsetof(struct icmp6hdr,
					    icmp6_dataun.u_echo.identifier);
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

	ret = snat_v6_rev_nat_handle_mapping(ctx, &tuple, fraginfo, &state, off, trace);
	if (ret < 0)
		return ret;

	/* Skip port rewrite for ICMPV6_PKT_TOOBIG by passing old_port == new_port == 0. */
	to_dport = state->to_dport;

rewrite:
	return snat_v6_rewrite_headers(ctx, tuple.nexthdr, ETH_HLEN,
				       ipfrag_has_l4_header(fraginfo), off,
				       &tuple.daddr, &state->to_daddr, IPV6_DADDR_OFF,
				       tuple.dport, to_dport, port_off);
}
#else /* defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT) */
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
#endif /* defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT) */

#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)
static __always_inline int
snat_remap_rfc6052(struct __ctx_buff *ctx, const struct iphdr *ip4, int l3_off)
{
	union v6addr src6, dst6;

	build_v4_in_v6_rfc6052(&src6, ip4->saddr);
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
snat_v6_has_v4_match_rfc6052(const struct ipv4_ct_tuple *tuple4)
{
	struct ipv6_ct_tuple tuple6;

	memset(&tuple6, 0, sizeof(tuple6));
	build_v4_in_v6_rfc6052(&tuple6.saddr, tuple4->saddr);
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
