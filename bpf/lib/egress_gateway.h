/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

#ifndef __EGRESS_GATEWAY_H_
#define __EGRESS_GATEWAY_H_

#ifdef ENABLE_EGRESS_GATEWAY

#include <bpf/compiler.h>
#include <bpf/ctx/ctx.h>

#include <linux/ip.h>

#include "maps.h"

/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of
 * an egress policy key (i.e. the source IP).
 */
#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

static __always_inline
int fill_egress_ct_key(struct ipv4_ct_tuple *ct_key, struct __ctx_buff *ctx,
		       const struct iphdr *ip4, int l4_off)
{
	struct {
		__be16 sport;
		__be16 dport;
	} ports;

	if (ctx_load_bytes(ctx, l4_off, &ports, 4) < 0)
		return DROP_INVALID;

	ct_key->saddr = ip4->saddr;
	ct_key->daddr = ip4->daddr;
	ct_key->nexthdr = ip4->protocol;
	ct_key->sport = ports.sport;
	ct_key->dport = ports.dport;

	return 0;
}

static __always_inline
struct egress_ct_entry *lookup_ip4_egress_ct(struct ipv4_ct_tuple *ct_key)
{
	return map_lookup_elem(&EGRESS_CT_MAP, ct_key);
}

static __always_inline
void update_egress_ct_entry(struct ipv4_ct_tuple *ct_key, __be32 gateway)
{
	struct egress_ct_entry egress_ct = {
		.gateway_ip = gateway
	};

	map_update_elem(&EGRESS_CT_MAP, ct_key, &egress_ct, 0);
}

static __always_inline
void fill_egress_key(struct egress_policy_key *key, __be32 saddr, __be32 daddr)
{
	key->lpm_key.prefixlen = EGRESS_IPV4_PREFIX;
	key->saddr = saddr;
	key->daddr = daddr;
}

static __always_inline
struct egress_policy_entry *lookup_ip4_egress_policy(struct egress_policy_key *key)
{
	return map_lookup_elem(&EGRESS_POLICY_MAP, key);
}

static __always_inline
__be32 pick_egress_gateway(const struct egress_policy_entry *policy)
{
	unsigned int index = get_prandom_u32() % policy->size;

	/* Just being extra defensive here while keeping the verifier happy.
	 * Userspace should always guarantee the invariant:
	 *     policy->size < EGRESS_MAX_GATEWAY_NODES"
	 */
	index %= EGRESS_MAX_GATEWAY_NODES;

	return policy->gateway_ips[index];
}

#endif /* ENABLE_EGRESS_GATEWAY */
#endif /* __EGRESS_GATEWAY_H_ */
