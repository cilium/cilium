/*
 *  Copyright (C) 2016-2018 Authors of Cilium
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

/**
 * Configuration:
 * LB_L4: Include L4 matching and rewriting capabilities
 * LB_L3: Enable fallback to L3 LB entries
 *
 * Either LB_L4, LB_L3, or both need to be set to enable forward
 * translation. Reverse translation will awlays occur regardless
 * of the settings.
 */


#ifndef __LB_H_
#define __LB_H_

#include "csum.h"
#include "conntrack.h"

#define CILIUM_LB_MAP_MAX_FE		256

#ifdef ENABLE_IPV6
struct bpf_elf_map __section_maps LB6_REVERSE_NAT_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(__u16),
	.size_value	= sizeof(struct lb6_reverse_nat),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
	.flags		= CONDITIONAL_PREALLOC,
};

struct bpf_elf_map __section_maps LB6_SERVICES_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct lb6_key),
	.size_value	= sizeof(struct lb6_service),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
	.flags		= CONDITIONAL_PREALLOC,
};

struct bpf_elf_map __section_maps LB6_SERVICES_MAP_V2 = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct lb6_key_v2),
	.size_value	= sizeof(struct lb6_service_v2),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
	.flags		= CONDITIONAL_PREALLOC,
};

struct bpf_elf_map __section_maps LB6_RR_SEQ_MAP = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(struct lb6_key),
	.size_value     = sizeof(struct lb_sequence),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = CILIUM_LB_MAP_MAX_FE,
	.flags		= CONDITIONAL_PREALLOC,
};

struct bpf_elf_map __section_maps LB6_RR_SEQ_MAP_V2 = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(struct lb6_key_v2),
	.size_value     = sizeof(struct lb_sequence),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = CILIUM_LB_MAP_MAX_FE,
	.flags		= CONDITIONAL_PREALLOC,
};

struct bpf_elf_map __section_maps LB6_BACKEND_MAP = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(__u16),
	.size_value     = sizeof(struct lb6_backend),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = CILIUM_LB_MAP_MAX_ENTRIES,
	.flags          = CONDITIONAL_PREALLOC,
};

#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
struct bpf_elf_map __section_maps LB4_REVERSE_NAT_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(__u16),
	.size_value	= sizeof(struct lb4_reverse_nat),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
	.flags		= CONDITIONAL_PREALLOC,
};

struct bpf_elf_map __section_maps LB4_SERVICES_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct lb4_key),
	.size_value	= sizeof(struct lb4_service),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
	.flags		= CONDITIONAL_PREALLOC,
};

struct bpf_elf_map __section_maps LB4_SERVICES_MAP_V2 = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct lb4_key_v2),
	.size_value	= sizeof(struct lb4_service_v2),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
	.flags		= CONDITIONAL_PREALLOC,
};

struct bpf_elf_map __section_maps LB4_RR_SEQ_MAP = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(struct lb4_key),
	.size_value     = sizeof(struct lb_sequence),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = CILIUM_LB_MAP_MAX_FE,
	.flags		= CONDITIONAL_PREALLOC,
};

struct bpf_elf_map __section_maps LB4_RR_SEQ_MAP_V2 = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(struct lb4_key_v2),
	.size_value     = sizeof(struct lb_sequence),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = CILIUM_LB_MAP_MAX_FE,
	.flags		= CONDITIONAL_PREALLOC,
};

struct bpf_elf_map __section_maps LB4_BACKEND_MAP = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(__u16),
	.size_value     = sizeof(struct lb4_backend),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = CILIUM_LB_MAP_MAX_ENTRIES,
	.flags          = CONDITIONAL_PREALLOC,
};

#endif /* ENABLE_IPV4 */


#define REV_NAT_F_TUPLE_SADDR 1
#ifdef LB_DEBUG
#define cilium_dbg_lb cilium_dbg
#else
#define cilium_dbg_lb(a, b, c, d)
#endif

#ifdef HAVE_MAP_VAL_ADJ
static inline int lb_next_rr(struct __sk_buff *skb,
			     struct lb_sequence *seq,
			     __be16 hash)
{
	int slave = 0;
	__u8 offset = hash % seq->count;

	if (offset < LB_RR_MAX_SEQ) {
		/* Slave 0 is reserved for the master slot */
		slave = seq->idx[offset] + 1;
		cilium_dbg(skb, DBG_RR_SLAVE_SEL, hash, slave);
	}

	return slave;
}
#endif

static inline __u32 lb_enforce_rehash(struct __sk_buff *skb)
{
#ifdef HAVE_SET_HASH_INVALID
	set_hash_invalid(skb);
#else
	/* Ugly workaround for 4.8 kernel where we don't have this function. */
	__u32 tmp;

	skb_load_bytes(skb,  0, &tmp, sizeof(tmp));
	skb_store_bytes(skb, 0, &tmp, sizeof(tmp), BPF_F_INVALIDATE_HASH);
#endif
	return get_hash_recalc(skb);
}

static inline int lb6_select_slave(struct __sk_buff *skb,
				   struct lb6_key *key,
				   __u16 count, __u16 weight)
{
	__u32 hash = lb_enforce_rehash(skb);
	int slave = 0;

/* Disabled for now since on older kernels dynamic map access
 * will cause a significant complexity increase for the entire
 * program due to pruning having less opportunities matching
 * register state in the verifier. For later kernels this is
 * less of a problem, so we can enabled to in future based on
 * changing the HAVE_MAP_VAL_ADJ probe. Thus just do the slave
 * selection based on hash instead of hash w/ weights.
 */
#if 0 /* HAVE_MAP_VAL_ADJ */
	if (weight) {
		struct lb_sequence *seq;

		seq = map_lookup_elem(&cilium_lb6_rr_seq, key);
		if (seq && seq->count != 0)
			slave = lb_next_rr(skb, seq, hash);
	}
#endif

	if (slave == 0) {
		/* Slave 0 is reserved for the master slot */
		slave = (hash % count) + 1;
		cilium_dbg(skb, DBG_PKT_HASH, hash, slave);
	}

	return slave;
}

static inline int lb4_select_slave(struct __sk_buff *skb,
				   struct lb4_key *key,
				   __u16 count, __u16 weight)
{
	__u32 hash = lb_enforce_rehash(skb);
	int slave = 0;

/* Disabled for now since on older kernels dynamic map access
 * will cause a significant complexity increase for the entire
 * program due to pruning having less opportunities matching
 * register state in the verifier. For later kernels this is
 * less of a problem, so we can enabled to in future based on
 * changing the HAVE_MAP_VAL_ADJ probe. Thus just do the slave
 * selection based on hash instead of hash w/ weights.
 */
#if 0 /* HAVE_MAP_VAL_ADJ */
	if (weight) {
		struct lb_sequence *seq;

		seq = map_lookup_elem(&cilium_lb4_rr_seq, key);
		if (seq && seq->count != 0)
			slave = lb_next_rr(skb, seq, hash);
	}
#endif

	if (slave == 0) {
		/* Slave 0 is reserved for the master slot */
		slave = (hash % count) + 1;
		cilium_dbg_lb(skb, DBG_PKT_HASH, hash, slave);
	}

	return slave;
}

static inline int __inline__ extract_l4_port(struct __sk_buff *skb, __u8 nexthdr,
					     int l4_off, __be16 *port)
{
	int ret;

	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/* Port offsets for UDP and TCP are the same */
		ret = l4_load_port(skb, l4_off + TCP_DPORT_OFF, port);
		if (IS_ERR(ret))
			return ret;
		break;

	case IPPROTO_ICMPV6:
	case IPPROTO_ICMP:
		break;

	default:
		/* Pass unknown L4 to stack */
		return DROP_UNKNOWN_L4;
	}

	return 0;
}

static inline int __inline__ reverse_map_l4_port(struct __sk_buff *skb, __u8 nexthdr,
						 __be16 port, int l4_off,
						 struct csum_offset *csum_off)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (port) {
			__be16 old_port;
			int ret;

			/* Port offsets for UDP and TCP are the same */
			ret = l4_load_port(skb, l4_off + TCP_SPORT_OFF, &old_port);
			if (IS_ERR(ret))
				return ret;

			if (port != old_port) {
				ret = l4_modify_port(skb, l4_off, TCP_SPORT_OFF,
						     csum_off, port, old_port);
				if (IS_ERR(ret))
					return ret;
			}
		}
		break;

	case IPPROTO_ICMPV6:
	case IPPROTO_ICMP:
		break;

	default:
		return DROP_UNKNOWN_L4;
	}

	return 0;
}

#ifdef ENABLE_IPV6
static inline int __inline__ __lb6_rev_nat(struct __sk_buff *skb, int l4_off,
					 struct csum_offset *csum_off,
					 struct ipv6_ct_tuple *tuple, int flags,
					 struct lb6_reverse_nat *nat)
{
	union v6addr old_saddr;
	union v6addr tmp;
	__u8 *new_saddr;
	__be32 sum;
	int ret;

	cilium_dbg_lb(skb, DBG_LB6_REVERSE_NAT, nat->address.p4, nat->port);

	if (nat->port) {
		ret = reverse_map_l4_port(skb, tuple->nexthdr, nat->port, l4_off, csum_off);
		if (IS_ERR(ret))
			return ret;
	}

	if (flags & REV_NAT_F_TUPLE_SADDR) {
		ipv6_addr_copy(&old_saddr, &tuple->saddr);
		ipv6_addr_copy(&tuple->saddr, &nat->address);
		new_saddr = tuple->saddr.addr;
	} else {
		if (ipv6_load_saddr(skb, ETH_HLEN, &old_saddr) < 0)
			return DROP_INVALID;

		ipv6_addr_copy(&tmp, &nat->address);
		new_saddr = tmp.addr;
	}

	ret = ipv6_store_saddr(skb, new_saddr, ETH_HLEN);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(old_saddr.addr, 16, new_saddr, 16, 0);
	if (csum_l4_replace(skb, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}

/** Perform IPv6 reverse NAT based on reverse NAT index
 * @arg skb		packet
 * @arg l4_off		offset to L4
 * @arg csum_off	offset to L4 checksum field
 * @arg csum_flags	checksum flags
 * @arg index		reverse NAT index
 * @arg tuple		tuple
 * @arg saddr_tuple	If set, tuple address will be updated with new source address
 */
static inline int __inline__ lb6_rev_nat(struct __sk_buff *skb, int l4_off,
					 struct csum_offset *csum_off, __u16 index,
					 struct ipv6_ct_tuple *tuple, int flags)
{
	struct lb6_reverse_nat *nat;

	cilium_dbg_lb(skb, DBG_LB6_REVERSE_NAT_LOOKUP, index, 0);
	nat = map_lookup_elem(&LB6_REVERSE_NAT_MAP, &index);
	if (nat == NULL)
		return 0;

	return __lb6_rev_nat(skb, l4_off, csum_off, tuple, flags, nat);
}

/** Extract IPv6 LB key from packet
 * @arg skb		packet
 * @arg tuple		tuple
 * @arg l4_off		Offset to L4 header
 * @arg key		Pointer to store LB key in
 * @arg csum_off	Pointer to store L4 checksum field offset and flags
 *
 * Expects the skb to be validated for direct packet access up to L4. Fills
 * lb6_key based on L4 nexthdr.
 *
 * Returns:
 *   - TC_ACT_OK on successful extraction
 *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)
 *   - Negative error code
 */
static inline int __inline__ lb6_extract_key(struct __sk_buff *skb, struct ipv6_ct_tuple *tuple,
					     int l4_off, struct lb6_key *key,
					     struct csum_offset *csum_off, int dir)
{
	union v6addr *addr;

	addr = (dir == CT_INGRESS) ? &tuple->saddr : &tuple->daddr;
	ipv6_addr_copy(&key->address, addr);
	csum_l4_offset_and_flags(tuple->nexthdr, csum_off);

#ifdef LB_L4
	return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
#else
	return 0;
#endif
}

static inline struct lb6_service *lb6_lookup_service(struct __sk_buff *skb,
						    struct lb6_key *key)
{
#ifdef LB_L4
	if (key->dport) {
		struct lb6_service *svc;

		cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
		svc = map_lookup_elem(&LB6_SERVICES_MAP, key);
		if (svc && svc->count != 0)
			return svc;

		key->dport = 0;
	}
#endif

#ifdef LB_L3
	if (1) {
		struct lb6_service *svc;

		cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
		svc = map_lookup_elem(&LB6_SERVICES_MAP, key);
		if (svc && svc->count != 0)
			return svc;
	}
#endif

	cilium_dbg_lb(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
	return NULL;
}

static inline struct lb6_service *lb6_lookup_slave(struct __sk_buff *skb,
						   struct lb6_key *key, __u16 slave)
{
	struct lb6_service *svc;

	key->slave = slave;
	cilium_dbg_lb(skb, DBG_LB6_LOOKUP_SLAVE, key->slave, key->dport);
	svc = map_lookup_elem(&LB6_SERVICES_MAP, key);
	if (svc != NULL) {
		cilium_dbg_lb(skb, DBG_LB6_LOOKUP_SLAVE_SUCCESS, svc->target.p4, svc->port);
		return svc;
	}

	return NULL;
}

static inline int __inline__ lb6_xlate(struct __sk_buff *skb, union v6addr *new_dst, __u8 nexthdr,
				       int l3_off, int l4_off, struct csum_offset *csum_off,
				       struct lb6_key *key, struct lb6_service *svc)
{
	ipv6_store_daddr(skb, new_dst->addr, l3_off);

	if (csum_off) {
		__be32 sum = csum_diff(key->address.addr, 16, new_dst->addr, 16, 0);
		if (csum_l4_replace(skb, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

#ifdef LB_L4
	if (svc->port && key->dport != svc->port &&
	    (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)) {
		__be16 tmp = svc->port;
		int ret;

		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(skb, l4_off, TCP_DPORT_OFF, csum_off, tmp, key->dport);
		if (IS_ERR(ret))
			return ret;
	}
#endif

	return TC_ACT_OK;
}

static inline int __inline__ lb6_local(void *map, struct __sk_buff *skb, int l3_off, int l4_off,
				       struct csum_offset *csum_off, struct lb6_key *key,
				       struct ipv6_ct_tuple *tuple, struct lb6_service *svc,
				       struct ct_state *state)
{
	__u32 monitor; // Deliberately ignored; regular CT will determine monitoring.
	union v6addr *addr;
	__u8 flags = tuple->flags;
	int ret;

	ret = ct_lookup6(map, tuple, skb, l4_off, CT_SERVICE, state, &monitor);
	switch(ret) {
	case CT_NEW:
		state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
		ret = ct_create6(map, tuple, skb, CT_SERVICE, state);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret)) {
			tuple->flags = flags;
			return DROP_NO_SERVICE;
		}
		break;
	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		break;
	default:
		tuple->flags = flags;
		return DROP_NO_SERVICE;
	}

	/* If the lookup fails it means the user deleted the backend out from
	 * underneath us. To resolve this fall back to hash. If this is a TCP
	 * session we are likely to get a TCP RST.
	 */
	if (!(svc = lb6_lookup_slave(skb, key, state->slave))) {
		if ((svc = lb6_lookup_service(skb, key)) == NULL) {
			tuple->flags = flags;
			return DROP_NO_SERVICE;
		}
		state->slave = lb6_select_slave(skb, key, svc->count, svc->weight);
		ct_update6_slave(map, tuple, state);
	}

	/* Restore flags so that SERVICE flag is only used in used when the
	 * service lookup happens and future lookups use EGRESS or INGRESS.
	 */
	tuple->flags = flags;
	ipv6_addr_copy(&tuple->daddr, &svc->target);
	addr = &tuple->daddr;

	if (state)
		state->rev_nat_index = svc->rev_nat_index;

	return lb6_xlate(skb, addr, tuple->nexthdr, l3_off, l4_off,
			 csum_off, key, svc);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static inline int __inline__ __lb4_rev_nat(struct __sk_buff *skb, int l3_off, int l4_off,
					 struct csum_offset *csum_off,
					 struct ipv4_ct_tuple *tuple, int flags,
					 struct lb4_reverse_nat *nat,
					 struct ct_state *ct_state)
{
	__be32 old_sip, new_sip, sum = 0;
	int ret;

	cilium_dbg_lb(skb, DBG_LB4_REVERSE_NAT, nat->address, nat->port);

	if (nat->port) {
		ret = reverse_map_l4_port(skb, tuple->nexthdr, nat->port, l4_off, csum_off);
		if (IS_ERR(ret))
			return ret;
	}

	if (flags & REV_NAT_F_TUPLE_SADDR) {
		old_sip = tuple->saddr;
		tuple->saddr = new_sip = nat->address;
	} else {
		ret = skb_load_bytes(skb, l3_off + offsetof(struct iphdr, saddr), &old_sip, 4);
		if (IS_ERR(ret))
			return ret;

		new_sip = nat->address;
	}

	if (ct_state->loopback) {
		/* The packet was looped back to the sending endpoint on the
		 * forward service translation. This implies that the original
		 * source address of the packet is the source address of the
		 * current packet. We therefore need to make the current source
		 * address the new destination address */
		__be32 old_dip;

		ret = skb_load_bytes(skb, l3_off + offsetof(struct iphdr, daddr), &old_dip, 4);
		if (IS_ERR(ret))
			return ret;

		cilium_dbg_lb(skb, DBG_LB4_LOOPBACK_SNAT_REV, old_dip, old_sip);

		ret = skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), &old_sip, 4, 0);
		if (IS_ERR(ret))
			return DROP_WRITE_ERROR;

		sum = csum_diff(&old_dip, 4, &old_sip, 4, 0);

		/* Update the tuple address which is representing the destination address */
		tuple->saddr = old_sip;
	}

        ret = skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), &new_sip, 4, 0);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(&old_sip, 4, &new_sip, 4, sum);
	if (l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
		return DROP_CSUM_L3;

	if (csum_off->offset &&
	    csum_l4_replace(skb, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}


/** Perform IPv4 reverse NAT based on reverse NAT index
 * @arg skb		packet
 * @arg l3_off		offset to L3
 * @arg l4_off		offset to L4
 * @arg csum_off	offset to L4 checksum field
 * @arg csum_flags	checksum flags
 * @arg index		reverse NAT index
 * @arg tuple		tuple
 */
static inline int __inline__ lb4_rev_nat(struct __sk_buff *skb, int l3_off, int l4_off,
					 struct csum_offset *csum_off,
					 struct ct_state *ct_state,
					 struct ipv4_ct_tuple *tuple, int flags)
{
	struct lb4_reverse_nat *nat;

	cilium_dbg_lb(skb, DBG_LB4_REVERSE_NAT_LOOKUP, ct_state->rev_nat_index, 0);
	nat = map_lookup_elem(&LB4_REVERSE_NAT_MAP, &ct_state->rev_nat_index);
	if (nat == NULL)
		return 0;

	return __lb4_rev_nat(skb, l3_off, l4_off, csum_off, tuple, flags, nat,
			     ct_state);
}

/** Extract IPv4 LB key from packet
 * @arg skb		packet
 * @arg tuple		tuple
 * @arg l4_off		Offset to L4 header
 * @arg key		Pointer to store LB key in
 * @arg csum_off	Pointer to store L4 checksum field offset  in
 *
 * Returns:
 *   - TC_ACT_OK on successful extraction
 *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)
 *   - Negative error code
 */
static inline int __inline__ lb4_extract_key(struct __sk_buff *skb, struct ipv4_ct_tuple *tuple,
					     int l4_off, struct lb4_key *key,
					     struct csum_offset *csum_off, int dir)
{
	key->address = (dir == CT_INGRESS) ? tuple->saddr : tuple->daddr;
	csum_l4_offset_and_flags(tuple->nexthdr, csum_off);

#ifdef LB_L4
	return extract_l4_port(skb, tuple->nexthdr, l4_off, &key->dport);
#else
	return 0;
#endif
}

static inline struct lb4_service *__lb4_lookup_service(struct lb4_key *key)
{
#ifdef LB_L4
	if (key->dport) {
		struct lb4_service *svc;

		/* FIXME: The verifier barks on these calls right now for some reason */
		/* cilium_dbg_lb(skb, DBG_LB4_LOOKUP_MASTER, key->address, key->dport); */
		svc = map_lookup_elem(&LB4_SERVICES_MAP, key);
		if (svc && svc->count != 0)
			return svc;

		key->dport = 0;
	}
#endif

#ifdef LB_L3
	if (1) {
		struct lb4_service *svc;

		/* FIXME: The verifier barks on these calls right now for some reason */
		/* cilium_dbg_lb(skb, DBG_LB4_LOOKUP_MASTER, key->address, key->dport); */
		svc = map_lookup_elem(&LB4_SERVICES_MAP, key);
		if (svc && svc->count != 0)
			return svc;
	}
#endif
	return NULL;
}

static inline struct lb4_service *lb4_lookup_service(struct __sk_buff *skb,
						     struct lb4_key *key)
{
	struct lb4_service *svc = __lb4_lookup_service(key);

	if (!svc)
		cilium_dbg_lb(skb, DBG_LB4_LOOKUP_MASTER_FAIL, 0, 0);
	return svc;
}

static inline struct lb4_service *lb4_lookup_slave(struct __sk_buff *skb,
						   struct lb4_key *key, __u16 slave)
{
	struct lb4_service *svc;

	key->slave = slave;
	cilium_dbg_lb(skb, DBG_LB4_LOOKUP_SLAVE, key->slave, key->dport);
	svc = map_lookup_elem(&LB4_SERVICES_MAP, key);
	if (svc != NULL) {
		cilium_dbg_lb(skb, DBG_LB4_LOOKUP_SLAVE_SUCCESS, svc->target, svc->port);
		return svc;
	}

	return NULL;
}

static inline int __inline__
lb4_xlate(struct __sk_buff *skb, __be32 *new_daddr, __be32 *new_saddr,
	  __be32 *old_saddr, __u8 nexthdr, int l3_off, int l4_off,
	  struct csum_offset *csum_off, struct lb4_key *key,
	  struct lb4_service *svc)
{
	int ret;
	__be32 sum;

	ret = skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), new_daddr, 4, 0);
	if (ret < 0)
		return DROP_WRITE_ERROR;

	sum = csum_diff(&key->address, 4, new_daddr, 4, 0);

	if (new_saddr && *new_saddr) {
		cilium_dbg_lb(skb, DBG_LB4_LOOPBACK_SNAT, *old_saddr, *new_saddr);
		ret = skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), new_saddr, 4, 0);
		if (ret < 0)
			return DROP_WRITE_ERROR;

		sum = csum_diff(old_saddr, 4, new_saddr, 4, sum);
	}

	if (l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
		return DROP_CSUM_L3;

	if (csum_off->offset) {
		if (csum_l4_replace(skb, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

#ifdef LB_L4
	if (svc->port && key->dport != svc->port &&
	    (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)) {
		__be16 tmp = svc->port;
		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(skb, l4_off, TCP_DPORT_OFF, csum_off, tmp, key->dport);
		if (IS_ERR(ret))
			return ret;
	}
#endif

	return TC_ACT_OK;
}

static inline int __inline__ lb4_local(void *map, struct __sk_buff *skb,
				       int l3_off, int l4_off,
				       struct csum_offset *csum_off, struct lb4_key *key,
				       struct ipv4_ct_tuple *tuple, struct lb4_service *svc,
				       struct ct_state *state, __be32 saddr)
{
	__u32 monitor; // Deliberately ignored; regular CT will determine monitoring.
	__be32 new_saddr = 0, new_daddr;
	__u8 flags = tuple->flags;
	int ret;

	ret = ct_lookup4(map, tuple, skb, l4_off, CT_SERVICE, state, &monitor);
	switch(ret) {
	case CT_NEW:
		state->slave = lb4_select_slave(skb, key, svc->count, svc->weight);
		ret = ct_create4(map, tuple, skb, CT_SERVICE, state);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret)) {
			tuple->flags = flags;
			return DROP_NO_SERVICE;
		}
		break;
	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		break;
	default:
		tuple->flags = flags;
		return DROP_NO_SERVICE;
	}

	/* If the lookup fails it means the user deleted the backend out from
	 * underneath us. To resolve this fall back to hash. If this is a TCP
	 * session we are likely to get a TCP RST.
	 */
	if (!(svc = lb4_lookup_slave(skb, key, state->slave))) {
		if ((svc = lb4_lookup_service(skb, key)) == NULL) {
			tuple->flags = flags;
			return DROP_NO_SERVICE;
		}
		state->slave = lb4_select_slave(skb, key, svc->count, svc->weight);
		ct_update4_slave(map, tuple, state);
	}

	/* Restore flags so that SERVICE flag is only used in used when the
	 * service lookup happens and future lookups use EGRESS or INGRESS.
	 */
	tuple->flags = flags;
	state->rev_nat_index = svc->rev_nat_index;
	state->addr = new_daddr = svc->target;

#ifndef DISABLE_LOOPBACK_LB
	/* Special loopback case: The origin endpoint has transmitted to a
	 * service which is being translated back to the source. This would
	 * result in a packet with identical source and destination address.
	 * Linux considers such packets as martian source and will drop unless
	 * received on a loopback device. Perform NAT on the source address
	 * to make it appear from an outside address.
	 */
	if (saddr == svc->target) {
		new_saddr = IPV4_LOOPBACK;
		state->loopback = 1;
		state->addr = new_saddr;
		state->svc_addr = saddr;
	}
#endif

	if (!state->loopback)
		tuple->daddr = svc->target;

	return lb4_xlate(skb, &new_daddr, &new_saddr, &saddr,
			 tuple->nexthdr, l3_off, l4_off, csum_off, key,
			 svc);
}
#endif /* ENABLE_IPV4 */

#endif /* __LB_H_ */
