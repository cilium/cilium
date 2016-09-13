/*
 *  Copyright (C) 2016 Authors of Cilium
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
#ifndef __LB_H_
#define __LB_H_

/* FIXME: Make configurable */
#define CILIUM_LB_MAP_SIZE	1024

__BPF_MAP(cilium_lb6_reverse_nat, BPF_MAP_TYPE_HASH, 0,
	  sizeof(__u16), sizeof(struct lb6_reverse_nat),
	  PIN_GLOBAL_NS, CILIUM_LB_MAP_SIZE);

__BPF_MAP(cilium_lb6_services, BPF_MAP_TYPE_HASH, 0,
	  sizeof(struct lb6_key), sizeof(struct lb6_service),
	  PIN_GLOBAL_NS, CILIUM_LB_MAP_SIZE);

__BPF_MAP(cilium_lb4_reverse_nat, BPF_MAP_TYPE_HASH, 0,
	  sizeof(__u16), sizeof(struct lb4_reverse_nat),
	  PIN_GLOBAL_NS, CILIUM_LB_MAP_SIZE);

__BPF_MAP(cilium_lb4_services, BPF_MAP_TYPE_HASH, 0,
	  sizeof(struct lb4_key), sizeof(struct lb4_service),
	  PIN_GLOBAL_NS, CILIUM_LB_MAP_SIZE);

static inline int lb_select_slave(struct __sk_buff *skb, __u16 count)
{
	__be16 hash = get_hash_recalc(skb);
	int slave;

	/* Slave 0 is reserved for the master slot */
	slave = (hash % count) + 1;
	cilium_trace(skb, DBG_PKT_HASH, hash, slave);

	return slave;
}

static inline int extract_l4_port(struct __sk_buff *skb, __u8 nexthdr, int l4_off,
				  int *csum_off, int *csum_flags, __u16 *port)
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

	*csum_off = l4_csum_offset_and_flags(nexthdr, csum_flags);

	return 0;
}

static inline int __inline__ reverse_map_l4_port(struct __sk_buff *skb, __u8 nexthdr,
						 __u16 port, int l4_off, int csum_off)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (port) {
			__u16 old_port;
			int ret;

			/* Port offsets for UDP and TCP are the same */
			ret = l4_load_port(skb, l4_off + TCP_SPORT_OFF, &old_port);
			if (IS_ERR(ret))
				return ret;

			if (port != old_port) {
				ret = l4_modify_port(skb, l4_off + TCP_SPORT_OFF,
						     l4_off + csum_off, port, old_port);
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

/** Perform IPv6 DSR SNAT based on reverse NAT index
 * @arg skb		packet
 * @arg l4_off		offset to L4
 * @arg csum_off	offset to L4 checksum field
 * @arg csum_flags	checksum flags
 * @arg index		reverse NAT index
 * @arg tuple		tuple
 */
static inline int lb6_dsr_snat(struct __sk_buff *skb, int l4_off, int csum_off,
			       int csum_flags, __u16 index, struct ipv6_ct_tuple *tuple)
{
	union v6addr tmp, sip;
	struct lb6_reverse_nat *nat;
	__be32 sum;
	int ret;

	cilium_trace(skb, DBG_LB6_REVERSE_NAT_LOOKUP, index, 0);
	nat = map_lookup_elem(&cilium_lb6_reverse_nat, &index);
	if (nat == NULL) {
		return 0;
	}

	cilium_trace(skb, DBG_LB6_REVERSE_NAT, nat->address.p4, nat->port);
	ret = reverse_map_l4_port(skb, tuple->nexthdr, nat->port, l4_off, csum_off);
	if (IS_ERR(ret))
		return ret;

	if (ipv6_load_saddr(skb, ETH_HLEN, &sip) < 0)
		return DROP_INVALID;

	ipv6_addr_copy(&tmp, &nat->address);
	ret = ipv6_store_saddr(skb, tmp.addr, ETH_HLEN);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(sip.addr, 16, tmp.addr, 16, 0);
	if (l4_csum_replace(skb, l4_off + csum_off, 0, sum, csum_flags | BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}

/** Extract IPv6 LB key from packet
 * @arg skb		packet
 * @arg tuple		tuple
 * @arg l4_off		Offset to L4 header
 * @arg key		Pointer to store LB key in
 * @arg csum_off	Pointer to store L4 checksum field offset  in
 * @arg csum_flags	Pointer to store L4 checksum flags
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
					     int l4_off, struct lb6_key *key, int *csum_off, int *csum_flags)
{
	ipv6_addr_copy(&key->address, &tuple->addr);
	return extract_l4_port(skb, tuple->nexthdr, l4_off, csum_off, csum_flags, &key->dport);
}

static inline struct lb6_service *lb6_lookup_service(struct __sk_buff *skb,
						    struct lb6_key *key)
{
	struct lb6_service *svc;

	cilium_trace(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
	svc = map_lookup_elem(&cilium_lb6_services, key);
	if (svc && svc->count != 0)
		return svc;

	if (key->dport != 0) {
		key->dport = 0;
		cilium_trace(skb, DBG_LB6_LOOKUP_MASTER, key->address.p4, key->dport);
		svc = map_lookup_elem(&cilium_lb6_services, key);
		if (svc && svc->count != 0)
			return svc;
	}

	cilium_trace(skb, DBG_LB6_LOOKUP_MASTER_FAIL, key->address.p2, key->address.p3);
	return NULL;
}

static inline struct lb6_service *lb6_lookup_slave(struct __sk_buff *skb,
						   struct lb6_key *key, __u16 slave)
{
	struct lb6_service *svc;

	key->slave = slave;
	cilium_trace(skb, DBG_LB6_LOOKUP_SLAVE, key->slave, key->dport);
	svc = map_lookup_elem(&cilium_lb6_services, key);
	if (svc != NULL) {
		cilium_trace(skb, DBG_LB6_LOOKUP_SLAVE_SUCCESS, svc->target.p4, svc->port);
		return svc;
	}

	return NULL;
}

static inline int __inline__ lb6_xlate(struct __sk_buff *skb, union v6addr *new_dst, __u8 nexthdr,
				       int l3_off, int l4_off, int csum_off, int csum_flags,
				       struct lb6_key *key, struct lb6_service *svc)
{
	int ret;

	ipv6_store_daddr(skb, new_dst->addr, l3_off);

	if (csum_off) {
		__be32 sum = csum_diff(key->address.addr, 16, new_dst->addr, 16, 0);
		if (l4_csum_replace(skb, l4_off + csum_off, 0, sum, BPF_F_PSEUDO_HDR | csum_flags) < 0)
			return DROP_CSUM_L4;
	}

	if (svc->port && key->dport != svc->port &&
	    (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)) {
		__u16 tmp = svc->port;
		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(skb, l4_off + TCP_DPORT_OFF,
				     l4_off + csum_off, tmp,
				     key->dport);
		if (IS_ERR(ret))
			return ret;
	}

	return TC_ACT_OK;
}

static inline int __inline__ lb6_local(struct __sk_buff *skb, int l3_off, int l4_off,
				       int csum_off, int csum_flags, struct lb6_key *key,
				       struct ipv6_ct_tuple *tuple, struct lb6_service *svc)
{
	__u16 slave;

	slave = lb_select_slave(skb, svc->count);
	if (!(svc = lb6_lookup_slave(skb, key, slave)))
		return DROP_NO_SERVICE;

	ipv6_addr_copy(&tuple->addr, &svc->target);

	return lb6_xlate(skb, &tuple->addr, tuple->nexthdr, l3_off, l4_off,
			 csum_off, csum_flags, key, svc);
}


/** Perform IPv4 DSR SNAT based on reverse NAT index
 * @arg skb		packet
 * @arg l3_off		offset to L3
 * @arg l4_off		offset to L4
 * @arg csum_off	offset to L4 checksum field
 * @arg csum_flags	checksum flags
 * @arg index		reverse NAT index
 * @arg tuple		tuple
 */
static inline int lb4_dsr_snat(struct __sk_buff *skb, int l3_off, int l4_off, int csum_off,
			       int csum_flags, __u16 index, struct ipv4_ct_tuple *tuple)
{
	__be32 old_sip, new_sip;
	struct lb4_reverse_nat *nat;
	__be32 sum;
	int ret;

	cilium_trace(skb, DBG_LB4_REVERSE_NAT_LOOKUP, index, 0);
	nat = map_lookup_elem(&cilium_lb4_reverse_nat, &index);
	if (nat == NULL) {
		return 0;
	}

	cilium_trace(skb, DBG_LB4_REVERSE_NAT, nat->address, nat->port);
	ret = reverse_map_l4_port(skb, tuple->nexthdr, nat->port, l4_off, csum_off);
	if (IS_ERR(ret))
		return ret;

        ret = skb_load_bytes(skb, l3_off + offsetof(struct iphdr, saddr), &old_sip, 4);
	if (IS_ERR(ret))
		return ret;

	new_sip = nat->address;
        ret = skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), &new_sip, 4, 0);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(&old_sip, 4, &new_sip, 4, 0);
	if (l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
		return DROP_CSUM_L3;

	if (csum_off &&
	    l4_csum_replace(skb, l4_off + csum_off, 0, sum, csum_flags | BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}

/** Extract IPv4 LB key from packet
 * @arg skb		packet
 * @arg tuple		tuple
 * @arg l4_off		Offset to L4 header
 * @arg key		Pointer to store LB key in
 * @arg csum_off	Pointer to store L4 checksum field offset  in
 * @arg csum_flags	Pointer to store L4 checksum flags
 *
 * Returns:
 *   - TC_ACT_OK on successful extraction
 *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)
 *   - Negative error code
 */
static inline int __inline__ lb4_extract_key(struct __sk_buff *skb, struct ipv4_ct_tuple *tuple,
					     int l4_off, struct lb4_key *key, int *csum_off, int *csum_flags)
{
	key->address = tuple->addr;
	return extract_l4_port(skb, tuple->nexthdr, l4_off, csum_off, csum_flags, &key->dport);
}

static inline struct lb4_service *lb4_lookup_service(struct __sk_buff *skb,
						     struct lb4_key *key)
{
	struct lb4_service *svc;

	cilium_trace(skb, DBG_LB4_LOOKUP_MASTER, key->address, key->dport);
	svc = map_lookup_elem(&cilium_lb4_services, key);
	if (svc && svc->count != 0)
		return svc;

	if (key->dport != 0) {
		key->dport = 0;
		cilium_trace(skb, DBG_LB4_LOOKUP_MASTER, key->address, key->dport);
		svc = map_lookup_elem(&cilium_lb4_services, key);
		if (svc && svc->count != 0)
			return svc;
	}

	cilium_trace(skb, DBG_LB4_LOOKUP_MASTER_FAIL, 0, 0);
	return NULL;
}

static inline struct lb4_service *lb4_lookup_slave(struct __sk_buff *skb,
						   struct lb4_key *key, __u16 slave)
{
	struct lb4_service *svc;

	key->slave = slave;
	cilium_trace(skb, DBG_LB4_LOOKUP_SLAVE, key->slave, key->dport);
	svc = map_lookup_elem(&cilium_lb4_services, key);
	if (svc != NULL) {
		cilium_trace(skb, DBG_LB4_LOOKUP_SLAVE_SUCCESS, svc->target, svc->port);
		return svc;
	}

	return NULL;
}

static inline int __inline__ lb4_xlate(struct __sk_buff *skb, __be32 *new_addr, __u8 nexthdr,
				       int l3_off, int l4_off, int csum_off, int csum_flags,
				       struct lb4_key *key, struct lb4_service *svc)
{
	int ret;
	__be32 sum;

	ret = skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), new_addr, 4, 0);
	if (ret < 0)
		return DROP_WRITE_ERROR;

	sum = csum_diff(&key->address, 4, new_addr, 4, 0);
	if (l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
		return DROP_CSUM_L3;

	if (csum_off) {
		if (l4_csum_replace(skb, l4_off + csum_off, 0, sum, BPF_F_PSEUDO_HDR | csum_flags) < 0)
			return DROP_CSUM_L4;
	}

	if (svc->port && key->dport != svc->port &&
	    (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)) {
		__u16 tmp = svc->port;
		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(skb, l4_off + TCP_DPORT_OFF,
				     l4_off + csum_off, tmp,
				     key->dport);
		if (IS_ERR(ret))
			return ret;
	}

	return TC_ACT_OK;
}

static inline int __inline__ lb4_local(struct __sk_buff *skb, int l3_off, int l4_off,
				       int csum_off, int csum_flags, struct lb4_key *key,
				       struct ipv4_ct_tuple *tuple, struct lb4_service *svc)
{
	__u16 slave;

	slave = lb_select_slave(skb, svc->count);
	if (!(svc = lb4_lookup_slave(skb, key, slave)))
		return DROP_NO_SERVICE;

	tuple->addr = svc->target;
	skb->cb[CB_REVERSE_NAT] = svc->rev_nat_index;

	return lb4_xlate(skb, &tuple->addr, tuple->nexthdr, l3_off, l4_off,
			 csum_off, csum_flags, key, svc);
}

#endif /* __LB_H_ */
