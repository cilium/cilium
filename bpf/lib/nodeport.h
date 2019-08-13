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

#ifndef __NODEPORT_H_
#define __NODEPORT_H_

#include <bpf/api.h>

#include "nat.h"
#include "lb.h"
#include "conntrack.h"
#include "csum.h"
#include "encap.h"

#define CB_SRC_IDENTITY	0

/* No nodeport on cilium_host interface. */
#ifdef FROM_HOST
# undef ENABLE_NODEPORT
# undef ENABLE_MASQUERADE
#endif

#ifdef ENABLE_NODEPORT

#ifdef ENABLE_IPV4
struct bpf_elf_map __section_maps NODEPORT_NEIGH4 = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(__be32),		// ipv4 addr
	.size_value	= sizeof(union macaddr),	// hw addr
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= SNAT_MAPPING_IPV4_SIZE,
};
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
struct bpf_elf_map __section_maps NODEPORT_NEIGH6 = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(union v6addr),		// ipv6 addr
	.size_value	= sizeof(union macaddr),	// hw addr
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= SNAT_MAPPING_IPV6_SIZE,
};
#endif /* ENABLE_IPV6 */

#endif /* ENABLE_NODEPORT */

static inline void bpf_clear_nodeport(struct __sk_buff *skb)
{
#ifdef ENABLE_NODEPORT
	skb->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;
#endif
}

#ifdef ENABLE_NODEPORT
static inline bool __inline__ bpf_skip_nodeport(struct __sk_buff *skb)
{
	volatile __u32 tc_index = skb->tc_index;
	skb->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;
	return tc_index & TC_INDEX_F_SKIP_NODEPORT;
}
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_NODEPORT
#ifdef ENABLE_IPV6
static __always_inline bool nodeport_nat_ipv6_needed(struct __sk_buff *skb,
						     union v6addr *addr, int dir)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return false;
	/* See nodeport_nat_ipv4_needed(). */
	if (dir == NAT_DIR_EGRESS)
		return !ipv6_addrcmp((union v6addr *)&ip6->saddr, addr);
	else
		return !ipv6_addrcmp((union v6addr *)&ip6->daddr, addr);
	return false;
}

#define NODEPORT_DO_NAT_IPV6(ADDR, NDIR)					\
	({									\
		struct ipv6_nat_target target = {				\
			.min_port = NODEPORT_PORT_MAX_NAT + 1,			\
			.max_port = 65535,					\
			.force_range = true,					\
		};								\
		ipv6_addr_copy(&target.addr, (ADDR));				\
		int ____ret = nodeport_nat_ipv6_needed(skb, (ADDR), (NDIR)) ?	\
			      snat_v6_process(skb, (NDIR), &target) : TC_ACT_OK;\
		____ret;							\
	})

static __always_inline int nodeport_nat_ipv6_fwd(struct __sk_buff *skb,
						 union v6addr *addr)
{
	return NODEPORT_DO_NAT_IPV6(addr, NAT_DIR_EGRESS);
}

static __always_inline int nodeport_nat_ipv6_rev(struct __sk_buff *skb,
						 union v6addr *addr)
{
	return NODEPORT_DO_NAT_IPV6(addr, NAT_DIR_INGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_NAT)
int tail_nodeport_nat_ipv6(struct __sk_buff *skb)
{
	int ifindex = NATIVE_DEV_IFINDEX, ret, dir = skb->cb[CB_NAT];
	struct bpf_fib_lookup fib_params = {};
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.force_range = true,
	};
	void *data, *data_end;
	struct ipv6hdr *ip6;

	BPF_V6(target.addr, IPV6_NODEPORT);
#ifdef ENCAP_IFINDEX
	if (dir == NAT_DIR_EGRESS) {
		struct remote_endpoint_info *info;
		union v6addr *dst;

		if (!revalidate_data(skb, &data, &data_end, &ip6))
			return DROP_INVALID;

		dst = (union v6addr *)&ip6->daddr;
		info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
		if (info != NULL && info->tunnel_endpoint != 0) {
			int ret = __encap_with_nodeid(skb, info->tunnel_endpoint,
						      SECLABEL, TRACE_PAYLOAD_LEN);
			if (ret)
				return ret;

			BPF_V6(target.addr, HOST_IP);
			ifindex = ENCAP_IFINDEX;

			/* fib lookup not necessary when going over tunnel. */
			if (eth_store_daddr(skb, fib_params.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(skb, fib_params.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	}
#endif
	ret = snat_v6_process(skb, dir, &target);
	if (IS_ERR(ret)) {
		/* In case of no mapping, recircle back to main path. SNAT is very
		 * expensive in terms of instructions (since we don't have BPF to
		 * BPF calls as we use tail calls) and complexity, hence this is
		 * done inside a tail call here.
		 */
		if (dir == NAT_DIR_INGRESS) {
			skb->tc_index |= TC_INDEX_F_SKIP_NODEPORT;
			ep_tail_call(skb, CILIUM_CALL_IPV6_FROM_LXC);
			ret = DROP_MISSED_TAIL_CALL;
		}
		goto drop_err;
	}

	skb->mark |= MARK_MAGIC_SNAT_DONE;
	if (dir == NAT_DIR_INGRESS) {
		ep_tail_call(skb, CILIUM_CALL_IPV6_NODEPORT_REVNAT);
		ret = DROP_MISSED_TAIL_CALL;
		goto drop_err;
	}
#ifdef ENCAP_IFINDEX
	if (ifindex == ENCAP_IFINDEX)
		goto out_send;
#endif
	if (!revalidate_data(skb, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	fib_params.family = AF_INET6;
	fib_params.ifindex = ifindex;
	ipv6_addr_copy((union v6addr *) &fib_params.ipv6_src, (union v6addr *) &ip6->saddr);
	ipv6_addr_copy((union v6addr *) &fib_params.ipv6_dst, (union v6addr *) &ip6->daddr);

	ret = fib_lookup(skb, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (ret != 0) {
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	if (eth_store_daddr(skb, fib_params.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(skb, fib_params.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	ifindex = fib_params.ifindex;
out_send:
	return redirect(ifindex, 0);
drop_err:
	return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT,
				      dir == NAT_DIR_INGRESS ?
				      METRIC_INGRESS : METRIC_EGRESS);
}

/* See nodeport_lb4(). */
static inline int nodeport_lb6(struct __sk_buff *skb, __u32 src_identity)
{
	int ret, l3_off = ETH_HLEN, l4_off, hdrlen;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	struct lb6_service_v2 *svc;
	struct lb6_key_v2 key = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	bool backend_local;
	__u32 monitor = 0;
	__u16 service_port;
	union macaddr smac;

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(skb, l3_off, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;

	ret = lb6_extract_key_v2(skb, &tuple, l4_off, &key, &csum_off, CT_EGRESS);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4)
			return TC_ACT_OK;
		else
			return ret;
	}

	service_port = bpf_ntohs(key.dport);
	if (service_port < NODEPORT_PORT_MIN ||
	    service_port > NODEPORT_PORT_MAX) {
		if (service_port >= NODEPORT_PORT_MIN_NAT &&
		    service_port <= NODEPORT_PORT_MAX_NAT) {
			skb->cb[CB_NAT] = NAT_DIR_INGRESS;
			skb->cb[CB_SRC_IDENTITY] = src_identity;
			ep_tail_call(skb, CILIUM_CALL_IPV6_NODEPORT_NAT);
			return DROP_MISSED_TAIL_CALL;
		}
		return TC_ACT_OK;
	}

	ct_state_new.orig_dport = key.dport;

	if ((svc = lb6_lookup_service_v2(skb, &key)) != NULL) {
		ret = lb6_local(get_ct_map6(&tuple), skb, l3_off, l4_off,
				&csum_off, &key, &tuple, svc, &ct_state_new);
		if (IS_ERR(ret))
			return ret;
	} else {
		return TC_ACT_OK;
	}

	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, skb, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;
	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	backend_local = lookup_ip6_endpoint(ip6);

	switch (ret) {
	case CT_NEW:
		ct_state_new.src_sec_id = SECLABEL;
		ct_state_new.node_port = 1;
		ret = ct_create6(get_ct_map6(&tuple), &tuple, skb, CT_EGRESS,
				 &ct_state_new, false);
		if (IS_ERR(ret))
			return ret;
		if (backend_local) {
			ct_flip_tuple_dir6(&tuple);
			ct_state_new.rev_nat_index = 0;
			ret = ct_create6(get_ct_map6(&tuple), &tuple, skb,
					 CT_INGRESS, &ct_state_new, false);
			if (IS_ERR(ret))
				return ret;
		}
		break;

	case CT_ESTABLISHED:
	case CT_REPLY:
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;
	if (eth_load_saddr(skb, &smac.addr, 0) < 0)
		return DROP_INVALID;
	ret = map_update_elem(&NODEPORT_NEIGH6, &ip6->saddr, &smac, 0);
	if (ret < 0) {
		return ret;
	}

	if (!backend_local) {
		skb->cb[CB_NAT] = NAT_DIR_EGRESS;
		ep_tail_call(skb, CILIUM_CALL_IPV6_NODEPORT_NAT);
		return DROP_MISSED_TAIL_CALL;
	}

	return TC_ACT_OK;
}

/* See comment in tail_rev_nodeport_lb4(). */
static inline int rev_nodeport_lb6(struct __sk_buff *skb, int *ifindex,
                                    union macaddr *mac)
{
	int ret, ret2, l3_off = ETH_HLEN, l4_off, hdrlen;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	struct ct_state ct_state = {};
	struct bpf_fib_lookup fib_params = {};
	union macaddr *dmac;
	__u32 monitor = 0;

	if (!revalidate_data(skb, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(skb, l3_off, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, skb, l4_off, CT_INGRESS, &ct_state,
			 &monitor);

	if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {
		ret2 = lb6_rev_nat(skb, l4_off, &csum_off, ct_state.rev_nat_index,
				   &tuple, REV_NAT_F_TUPLE_SADDR);
		if (IS_ERR(ret2))
			return ret2;

		if (!revalidate_data(skb, &data, &data_end, &ip6))
			return DROP_INVALID;

		skb->mark |= MARK_MAGIC_SNAT_DONE;
#ifdef ENCAP_IFINDEX
		{
			union v6addr *dst = (union v6addr *)&ip6->daddr;
			struct remote_endpoint_info *info;

			info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
			if (info != NULL && info->tunnel_endpoint != 0) {
				int ret = __encap_with_nodeid(skb, info->tunnel_endpoint,
							      SECLABEL, TRACE_PAYLOAD_LEN);
				if (ret)
					return ret;

				*ifindex = ENCAP_IFINDEX;

				/* fib lookup not necessary when going over tunnel. */
				if (eth_store_daddr(skb, fib_params.dmac, 0) < 0)
					return DROP_WRITE_ERROR;
				if (eth_store_saddr(skb, fib_params.smac, 0) < 0)
					return DROP_WRITE_ERROR;

				return TC_ACT_OK;
			}
		}
#endif

		dmac = map_lookup_elem(&NODEPORT_NEIGH6, &tuple.daddr);
		if (dmac) {
			if (eth_store_daddr(skb, &dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(skb, &mac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
		} else {
			fib_params.family = AF_INET6;
			fib_params.ifindex = *ifindex;

			ipv6_addr_copy((union v6addr *) &fib_params.ipv6_src, &tuple.saddr);
			ipv6_addr_copy((union v6addr *) &fib_params.ipv6_dst, &tuple.daddr);

			int rc = fib_lookup(skb, &fib_params, sizeof(fib_params),
					BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
			if (rc != 0)
				return DROP_NO_FIB;

			if (eth_store_daddr(skb, fib_params.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(skb, fib_params.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}

	}

	return TC_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_REVNAT)
int tail_rev_nodeport_lb6(struct __sk_buff *skb)
{
	int ifindex = NATIVE_DEV_IFINDEX;
	union macaddr mac = NATIVE_DEV_MAC;
	int ret = 0;

	ret = rev_nodeport_lb6(skb, &ifindex, &mac);
	if (IS_ERR(ret))
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, METRIC_EGRESS);
	return redirect(ifindex, 0);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline bool nodeport_nat_ipv4_needed(struct __sk_buff *skb,
						     __be32 addr, int dir)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return false;
	/* Basic minimum is to only NAT when there is a potential of
	 * overlapping tuples, e.g. applications in hostns reusing
	 * source IPs we SNAT in node-port.
	 */
	if (dir == NAT_DIR_EGRESS)
		return ip4->saddr == addr;
	else
		return ip4->daddr == addr;
	return false;
}

#define NODEPORT_DO_NAT_IPV4(ADDR, NDIR)					\
	({									\
		struct ipv4_nat_target target = {				\
			.min_port = NODEPORT_PORT_MAX_NAT + 1,			\
			.max_port = 65535,					\
			.addr = (ADDR),						\
			.force_range = true,					\
		};								\
		int ____ret = nodeport_nat_ipv4_needed(skb, (ADDR), (NDIR)) ?	\
			      snat_v4_process(skb, (NDIR), &target) : TC_ACT_OK;\
		____ret;							\
	})

static __always_inline int nodeport_nat_ipv4_fwd(struct __sk_buff *skb,
						 const __be32 addr)
{
	return NODEPORT_DO_NAT_IPV4(addr, NAT_DIR_EGRESS);
}

static __always_inline int nodeport_nat_ipv4_rev(struct __sk_buff *skb,
						 const __be32 addr)
{
	return NODEPORT_DO_NAT_IPV4(addr, NAT_DIR_INGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_NAT)
int tail_nodeport_nat_ipv4(struct __sk_buff *skb)
{
	int ifindex = NATIVE_DEV_IFINDEX, ret, dir = skb->cb[CB_NAT];
	struct bpf_fib_lookup fib_params = {};
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.force_range = true,
	};
	void *data, *data_end;
	struct iphdr *ip4;

	target.addr = IPV4_NODEPORT;
#ifdef ENCAP_IFINDEX
	if (dir == NAT_DIR_EGRESS) {
		struct remote_endpoint_info *info;

		if (!revalidate_data(skb, &data, &data_end, &ip4))
			return DROP_INVALID;

		info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
		if (info != NULL && info->tunnel_endpoint != 0) {
			int ret = __encap_with_nodeid(skb, info->tunnel_endpoint,
						      SECLABEL, TRACE_PAYLOAD_LEN);
			if (ret)
				return ret;

			target.addr = IPV4_GATEWAY;
			ifindex = ENCAP_IFINDEX;

			/* fib lookup not necessary when going over tunnel. */
			if (eth_store_daddr(skb, fib_params.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(skb, fib_params.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	}
#endif
	ret = snat_v4_process(skb, dir, &target);
	if (IS_ERR(ret)) {
		/* In case of no mapping, recircle back to main path. SNAT is very
		 * expensive in terms of instructions (since we don't have BPF to
		 * BPF calls as we use tail calls) and complexity, hence this is
		 * done inside a tail call here.
		 */
		if (dir == NAT_DIR_INGRESS) {
			skb->tc_index |= TC_INDEX_F_SKIP_NODEPORT;
			ep_tail_call(skb, CILIUM_CALL_IPV4_FROM_LXC);
			ret = DROP_MISSED_TAIL_CALL;
		}
		goto drop_err;
	}

	skb->mark |= MARK_MAGIC_SNAT_DONE;
	if (dir == NAT_DIR_INGRESS) {
		ep_tail_call(skb, CILIUM_CALL_IPV4_NODEPORT_REVNAT);
		ret = DROP_MISSED_TAIL_CALL;
		goto drop_err;
	}
#ifdef ENCAP_IFINDEX
	if (ifindex == ENCAP_IFINDEX)
		goto out_send;
#endif
	if (!revalidate_data(skb, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	fib_params.family = AF_INET;
	fib_params.ifindex = ifindex;
	fib_params.ipv4_src = ip4->saddr;
	fib_params.ipv4_dst = ip4->daddr;

	ret = fib_lookup(skb, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (ret != 0) {
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	if (eth_store_daddr(skb, fib_params.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(skb, fib_params.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	ifindex = fib_params.ifindex;
out_send:
	return redirect(ifindex, 0);
drop_err:
	return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT,
				      dir == NAT_DIR_INGRESS ?
				      METRIC_INGRESS : METRIC_EGRESS);
}

/* Main node-port entry point for host-external ingressing node-port traffic
 * which handles the case of: i) backend is local EP, ii) backend is remote EP,
 * iii) reply from remote backend EP.
 */
static inline int nodeport_lb4(struct __sk_buff *skb, __u32 src_identity)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	int ret,  l3_off = ETH_HLEN, l4_off;
	struct csum_offset csum_off = {};
	struct lb4_service_v2 *svc;
	struct lb4_key_v2 key = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	bool backend_local;
	__u32 monitor = 0;
	__u16 service_port;
	union macaddr smac;

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);

	ret = lb4_extract_key_v2(skb, &tuple, l4_off, &key, &csum_off, CT_EGRESS);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNKNOWN_L4)
			return TC_ACT_OK;
		else
			return ret;
	}

	service_port = bpf_ntohs(key.dport);
	if (service_port < NODEPORT_PORT_MIN ||
	    service_port > NODEPORT_PORT_MAX) {
		if (service_port >= NODEPORT_PORT_MIN_NAT &&
		    service_port <= NODEPORT_PORT_MAX_NAT) {
			skb->cb[CB_NAT] = NAT_DIR_INGRESS;
			skb->cb[CB_SRC_IDENTITY] = src_identity;
			ep_tail_call(skb, CILIUM_CALL_IPV4_NODEPORT_NAT);
			return DROP_MISSED_TAIL_CALL;
		}
		return TC_ACT_OK;
	}

	ct_state_new.orig_dport = key.dport;

	if ((svc = lb4_lookup_service_v2(skb, &key)) != NULL) {
		ret = lb4_local(get_ct_map4(&tuple), skb, l3_off, l4_off, &csum_off,
				&key, &tuple, svc, &ct_state_new, ip4->saddr);
		if (IS_ERR(ret))
			return ret;
	} else {
		return TC_ACT_OK;
	}

	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, skb, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;
	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	backend_local = lookup_ip4_endpoint(ip4);

	switch (ret) {
	case CT_NEW:
		ct_state_new.src_sec_id = SECLABEL;
		ct_state_new.node_port = 1;
		ret = ct_create4(get_ct_map4(&tuple), &tuple, skb, CT_EGRESS,
				 &ct_state_new, false);
		if (IS_ERR(ret))
			return ret;
		if (backend_local) {
			ct_flip_tuple_dir4(&tuple);
			ct_state_new.rev_nat_index = 0;
			ret = ct_create4(get_ct_map4(&tuple), &tuple, skb,
					 CT_INGRESS, &ct_state_new, false);
			if (IS_ERR(ret))
				return ret;
		}
		break;

	case CT_ESTABLISHED:
	case CT_REPLY:
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;
	if (eth_load_saddr(skb, &smac.addr, 0) < 0)
		return DROP_INVALID;
	ret = map_update_elem(&NODEPORT_NEIGH4, &ip4->saddr, &smac, 0);
	if (ret < 0) {
		return ret;
	}

	if (!backend_local) {
		skb->cb[CB_NAT] = NAT_DIR_EGRESS;
		ep_tail_call(skb, CILIUM_CALL_IPV4_NODEPORT_NAT);
		return DROP_MISSED_TAIL_CALL;
	}

	return TC_ACT_OK;
}

/* Reverse NAT handling of node-port traffic for the case where the
 * backend i) was a local EP and bpf_lxc redirected to us, ii) was
 * a remote backend and we got here after reverse SNAT from the
 * tail_nodeport_nat_ipv4().
 *
 * CILIUM_CALL_IPV{4,6}_NODEPORT_REVNAT is plugged into CILIUM_MAP_CALLS
 * of the bpf_netdev, bpf_overlay and of the bpf_lxc.
 */
static inline int rev_nodeport_lb4(struct __sk_buff *skb, int *ifindex,
				   union macaddr *mac)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct csum_offset csum_off = {};
	int ret, ret2, l3_off = ETH_HLEN, l4_off;
	struct ct_state ct_state = {};
	struct bpf_fib_lookup fib_params = {};
	union macaddr *dmac;
	__u32 monitor = 0;

	if (!revalidate_data(skb, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, skb, l4_off, CT_INGRESS, &ct_state,
			 &monitor);

	if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {
		ret2 = lb4_rev_nat(skb, l3_off, l4_off, &csum_off,
				   &ct_state, &tuple,
				   REV_NAT_F_TUPLE_SADDR);
		if (IS_ERR(ret2))
			return ret2;

		if (!revalidate_data(skb, &data, &data_end, &ip4))
			return DROP_INVALID;

		skb->mark |= MARK_MAGIC_SNAT_DONE;
#ifdef ENCAP_IFINDEX
		{
			struct remote_endpoint_info *info;

			info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
			if (info != NULL && info->tunnel_endpoint != 0) {
				int ret = __encap_with_nodeid(skb, info->tunnel_endpoint,
							      SECLABEL, TRACE_PAYLOAD_LEN);
				if (ret)
					return ret;

				*ifindex = ENCAP_IFINDEX;

				/* fib lookup not necessary when going over tunnel. */
				if (eth_store_daddr(skb, fib_params.dmac, 0) < 0)
					return DROP_WRITE_ERROR;
				if (eth_store_saddr(skb, fib_params.smac, 0) < 0)
					return DROP_WRITE_ERROR;

				return TC_ACT_OK;
			}
		}
#endif

		dmac = map_lookup_elem(&NODEPORT_NEIGH4, &ip4->daddr);
		if (dmac) {
		    if (eth_store_daddr(skb, &dmac->addr, 0) < 0)
			return DROP_WRITE_ERROR;
		    if (eth_store_saddr(skb, &mac->addr, 0) < 0)
			return DROP_WRITE_ERROR;
		} else {
		    fib_params.family = AF_INET;
		    fib_params.ifindex = *ifindex;

		    fib_params.ipv4_src = ip4->saddr;
		    fib_params.ipv4_dst = ip4->daddr;

		    int rc = fib_lookup(skb, &fib_params, sizeof(fib_params),
				BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
		    if (rc != 0)
			return DROP_NO_FIB;

		    if (eth_store_daddr(skb, fib_params.dmac, 0) < 0)
			return DROP_WRITE_ERROR;
		    if (eth_store_saddr(skb, fib_params.smac, 0) < 0)
			return DROP_WRITE_ERROR;
		}
	}

	return TC_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_REVNAT)
int tail_rev_nodeport_lb4(struct __sk_buff *skb)
{
	int ifindex = NATIVE_DEV_IFINDEX;
	union macaddr mac = NATIVE_DEV_MAC;
	int ret = 0;

	ret = rev_nodeport_lb4(skb, &ifindex, &mac);
	if (IS_ERR(ret))
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, METRIC_EGRESS);
	return redirect(ifindex, 0);
}
#endif /* ENABLE_IPV4 */

static __always_inline int nodeport_nat_fwd(struct __sk_buff *skb,
					    const bool encap)
{
	__u16 proto;

	if (!validate_ethertype(skb, &proto))
		return TC_ACT_OK;
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		__be32 addr;
#ifdef ENCAP_IFINDEX
		if (encap)
			addr = IPV4_GATEWAY;
		else
#endif
			addr = IPV4_NODEPORT;
		return nodeport_nat_ipv4_fwd(skb, addr);
	}
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		union v6addr addr;
#ifdef ENCAP_IFINDEX
		if (encap)
			BPF_V6(addr, HOST_IP);
		else
#endif
			BPF_V6(addr, IPV6_NODEPORT);
		return nodeport_nat_ipv6_fwd(skb, &addr);
	}
#endif /* ENABLE_IPV6 */
	default:
		break;
	}
	return TC_ACT_OK;
}

static __always_inline int nodeport_nat_rev(struct __sk_buff *skb,
					    const bool encap)
{
	__u16 proto;

	if (!validate_ethertype(skb, &proto))
		return TC_ACT_OK;
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		__be32 addr;
#ifdef ENCAP_IFINDEX
		if (encap)
			addr = IPV4_GATEWAY;
		else
#endif
			addr = IPV4_NODEPORT;
		return nodeport_nat_ipv4_rev(skb, addr);
	}
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		union v6addr addr;
#ifdef ENCAP_IFINDEX
		if (encap)
			BPF_V6(addr, HOST_IP);
		else
#endif
			BPF_V6(addr, IPV6_NODEPORT);
		return nodeport_nat_ipv6_rev(skb, &addr);
	}
#endif /* ENABLE_IPV6 */
	default:
		build_bug_on(!(NODEPORT_PORT_MIN_NAT < NODEPORT_PORT_MAX_NAT));
		build_bug_on(!(NODEPORT_PORT_MIN     < NODEPORT_PORT_MAX));
		build_bug_on(!(NODEPORT_PORT_MAX     < NODEPORT_PORT_MIN_NAT));
		build_bug_on(!(NODEPORT_PORT_MAX     < EPHERMERAL_MIN));
		break;
	}
	return TC_ACT_OK;
}
#endif /* ENABLE_NODEPORT */
#endif /* __NODEPORT_H_ */
