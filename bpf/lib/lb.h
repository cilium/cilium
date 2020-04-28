/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

/**
 * Configuration:
 * LB_L4: Include L4 matching and rewriting capabilities
 * LB_L3: Enable fallback to L3 LB entries
 *
 * Either LB_L4, LB_L3, or both need to be set to enable forward
 * translation. Reverse translation will always occur regardless
 * of the settings.
 */
#ifndef __LB_H_
#define __LB_H_

#include "csum.h"
#include "conntrack.h"
#include "ipv4.h"

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

struct bpf_elf_map __section_maps LB6_SERVICES_MAP_V2 = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct lb6_key),
	.size_value	= sizeof(struct lb6_service),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
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

#ifdef ENABLE_SESSION_AFFINITY
struct bpf_elf_map __section_maps LB6_AFFINITY_MAP = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(struct lb6_affinity_key),
	.size_value	= sizeof(struct lb_affinity_val),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
};
#endif

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

struct bpf_elf_map __section_maps LB4_SERVICES_MAP_V2 = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct lb4_key),
	.size_value	= sizeof(struct lb4_service),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
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

#ifdef ENABLE_SESSION_AFFINITY
struct bpf_elf_map __section_maps LB4_AFFINITY_MAP = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.size_key	= sizeof(struct lb4_affinity_key),
	.size_value	= sizeof(struct lb_affinity_val),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
};
#endif

#endif /* ENABLE_IPV4 */

#ifdef ENABLE_SESSION_AFFINITY
struct bpf_elf_map __section_maps LB_AFFINITY_MATCH_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct lb_affinity_match),
	.size_value	= sizeof(__u8), /* dummy value, map is used as a set */
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
	.flags		= CONDITIONAL_PREALLOC,
};
#endif

#define REV_NAT_F_TUPLE_SADDR 1
#ifdef LB_DEBUG
#define cilium_dbg_lb cilium_dbg
#else
#define cilium_dbg_lb(a, b, c, d)
#endif

static __always_inline
bool lb4_svc_is_nodeport(const struct lb4_service *svc __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	return svc->nodeport;
#else
	return false;
#endif /* ENABLE_NODEPORT */
}

static __always_inline
bool lb6_svc_is_nodeport(const struct lb6_service *svc __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	return svc->nodeport;
#else
	return false;
#endif /* ENABLE_NODEPORT */
}

static __always_inline
bool lb4_svc_is_external_ip(const struct lb4_service *svc __maybe_unused)
{
#ifdef ENABLE_EXTERNAL_IP
	return svc->external;
#else
	return false;
#endif
}

static __always_inline
bool lb6_svc_is_external_ip(const struct lb6_service *svc __maybe_unused)
{
#ifdef ENABLE_EXTERNAL_IP
	return svc->external;
#else
	return false;
#endif
}

static __always_inline
bool lb4_svc_is_hostport(const struct lb4_service *svc __maybe_unused)
{
#ifdef ENABLE_HOSTPORT
	return svc->hostport;
#else
	return false;
#endif /* ENABLE_HOSTPORT */
}

static __always_inline
bool lb6_svc_is_hostport(const struct lb6_service *svc __maybe_unused)
{
#ifdef ENABLE_HOSTPORT
	return svc->hostport;
#else
	return false;
#endif /* ENABLE_HOSTPORT */
}

static __always_inline int lb6_select_slave(__u16 count)
{
	/* Slave 0 is reserved for the master slot */
	return (get_prandom_u32() % count) + 1;
}

static __always_inline int lb4_select_slave(__u16 count)
{
	/* Slave 0 is reserved for the master slot */
	return (get_prandom_u32() % count) + 1;
}

static __always_inline int extract_l4_port(struct __ctx_buff *ctx, __u8 nexthdr,
					   int l4_off, __be16 *port,
					   __maybe_unused struct iphdr *ip4)
{
	int ret;

	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_IPV4_FRAGMENTS
		if (ip4) {
			struct ipv4_frag_l4ports ports = { };

			if (unlikely(ipv4_is_fragment(ip4))) {
				ret = ipv4_handle_fragment(ctx, ip4, l4_off,
							   &ports);
				if (IS_ERR(ret))
					return ret;
				*port = ports.dport;
				break;
			}
		}
#endif
		/* Port offsets for UDP and TCP are the same */
		ret = l4_load_port(ctx, l4_off + TCP_DPORT_OFF, port);
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

static __always_inline int reverse_map_l4_port(struct __ctx_buff *ctx, __u8 nexthdr,
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
			ret = l4_load_port(ctx, l4_off + TCP_SPORT_OFF, &old_port);
			if (IS_ERR(ret))
				return ret;

			if (port != old_port) {
				ret = l4_modify_port(ctx, l4_off, TCP_SPORT_OFF,
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
static __always_inline int __lb6_rev_nat(struct __ctx_buff *ctx, int l4_off,
					 struct csum_offset *csum_off,
					 struct ipv6_ct_tuple *tuple, int flags,
					 struct lb6_reverse_nat *nat)
{
	union v6addr old_saddr;
	union v6addr tmp;
	__u8 *new_saddr;
	__be32 sum;
	int ret;

	cilium_dbg_lb(ctx, DBG_LB6_REVERSE_NAT, nat->address.p4, nat->port);

	if (nat->port) {
		ret = reverse_map_l4_port(ctx, tuple->nexthdr, nat->port, l4_off, csum_off);
		if (IS_ERR(ret))
			return ret;
	}

	if (flags & REV_NAT_F_TUPLE_SADDR) {
		ipv6_addr_copy(&old_saddr, &tuple->saddr);
		ipv6_addr_copy(&tuple->saddr, &nat->address);
		new_saddr = tuple->saddr.addr;
	} else {
		if (ipv6_load_saddr(ctx, ETH_HLEN, &old_saddr) < 0)
			return DROP_INVALID;

		ipv6_addr_copy(&tmp, &nat->address);
		new_saddr = tmp.addr;
	}

	ret = ipv6_store_saddr(ctx, new_saddr, ETH_HLEN);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(old_saddr.addr, 16, new_saddr, 16, 0);
	if (csum_l4_replace(ctx, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}

/** Perform IPv6 reverse NAT based on reverse NAT index
 * @arg ctx		packet
 * @arg l4_off		offset to L4
 * @arg csum_off	offset to L4 checksum field
 * @arg csum_flags	checksum flags
 * @arg index		reverse NAT index
 * @arg tuple		tuple
 * @arg saddr_tuple	If set, tuple address will be updated with new source address
 */
static __always_inline int lb6_rev_nat(struct __ctx_buff *ctx, int l4_off,
				       struct csum_offset *csum_off, __u16 index,
				       struct ipv6_ct_tuple *tuple, int flags)
{
	struct lb6_reverse_nat *nat;

	cilium_dbg_lb(ctx, DBG_LB6_REVERSE_NAT_LOOKUP, index, 0);
	nat = map_lookup_elem(&LB6_REVERSE_NAT_MAP, &index);
	if (nat == NULL)
		return 0;

	return __lb6_rev_nat(ctx, l4_off, csum_off, tuple, flags, nat);
}

/** Extract IPv6 LB key from packet
 * @arg ctx		Packet
 * @arg tuple		Tuple
 * @arg l4_off		Offset to L4 header
 * @arg key		Pointer to store LB key in
 * @arg csum_off	Pointer to store L4 checksum field offset and flags
 * @arg dir		Flow direction
 *
 * Expects the ctx to be validated for direct packet access up to L4. Fills
 * lb6_key based on L4 nexthdr.
 *
 * Returns:
 *   - CTX_ACT_OK on successful extraction
 *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)
 *   - Negative error code
 */
static __always_inline int lb6_extract_key(struct __ctx_buff *ctx __maybe_unused,
					   struct ipv6_ct_tuple *tuple,
					   int l4_off __maybe_unused,
					   struct lb6_key *key,
					   struct csum_offset *csum_off,
					   int dir)
{
	union v6addr *addr;
	// FIXME(brb): set after adding support for different L4 protocols in LB
	key->proto = 0;
	addr = (dir == CT_INGRESS) ? &tuple->saddr : &tuple->daddr;
	ipv6_addr_copy(&key->address, addr);
	csum_l4_offset_and_flags(tuple->nexthdr, csum_off);

#ifdef LB_L4
	return extract_l4_port(ctx, tuple->nexthdr, l4_off, &key->dport, NULL);
#else
	return 0;
#endif
}

static __always_inline
struct lb6_service *lb6_lookup_service(struct lb6_key *key)
{
	key->slave = 0;
#ifdef LB_L4
	if (key->dport) {
		struct lb6_service *svc;

		/* FIXME: The verifier barks on these calls right now for some reason */
		/* cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_MASTER, key->address, key->dport); */
		svc = map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
		if (svc && svc->count != 0)
			return svc;

		key->dport = 0;
	}
#endif

#ifdef LB_L3
	if (1) {
		struct lb6_service *svc;

		/* FIXME: The verifier barks on these calls right now for some reason */
		/* cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_MASTER, key->address, key->dport); */
		svc = map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
		if (svc && svc->count != 0)
			return svc;
	}
#endif
	return NULL;
}

static __always_inline struct lb6_backend *__lb6_lookup_backend(__u16 backend_id)
{
	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
}

static __always_inline struct lb6_backend *
lb6_lookup_backend(struct __ctx_buff *ctx __maybe_unused, __u16 backend_id)
{
	struct lb6_backend *backend;

	backend = __lb6_lookup_backend(backend_id);
	if (!backend) {
		cilium_dbg_lb(ctx, DBG_LB6_LOOKUP_BACKEND_FAIL, backend_id, 0);
	}

	return backend;
}

static __always_inline
struct lb6_service *__lb6_lookup_slave(struct lb6_key *key)
{
	return map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
}

static __always_inline
struct lb6_service *lb6_lookup_slave(struct __ctx_buff *ctx __maybe_unused,
				     struct lb6_key *key, __u16 slave)
{
	struct lb6_service *svc;

	key->slave = slave;
	cilium_dbg_lb(ctx, DBG_LB6_LOOKUP_SLAVE, key->slave, key->dport);
	svc = __lb6_lookup_slave(key);
	if (svc != NULL) {
		return svc;
	}

	cilium_dbg_lb(ctx, DBG_LB6_LOOKUP_SLAVE_V2_FAIL, key->slave, key->dport);

	return NULL;
}

static __always_inline int lb6_xlate(struct __ctx_buff *ctx,
				     union v6addr *new_dst, __u8 nexthdr __maybe_unused,
				     int l3_off, int l4_off,
				     struct csum_offset *csum_off,
				     const struct lb6_key *key,
				     const struct lb6_backend *backend __maybe_unused)
{
	ipv6_store_daddr(ctx, new_dst->addr, l3_off);

	if (csum_off) {
		__be32 sum = csum_diff(key->address.addr, 16, new_dst->addr, 16, 0);
		if (csum_l4_replace(ctx, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

#ifdef LB_L4
	if (backend->port && key->dport != backend->port &&
	    (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)) {
		__be16 tmp = backend->port;
		int ret;

		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(ctx, l4_off, TCP_DPORT_OFF, csum_off, tmp, key->dport);
		if (IS_ERR(ret))
			return ret;
	}
#endif

	return CTX_ACT_OK;
}

#ifdef ENABLE_SESSION_AFFINITY
static __always_inline __u32
__lb6_affinity_backend_id(const struct lb6_service *svc, bool netns_cookie,
			  union lb6_affinity_client_id *id)
{
	__u32 now = bpf_ktime_get_sec();
	struct lb_affinity_match match = {
		.rev_nat_id	= svc->rev_nat_index,
	};
	struct lb6_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
	};
	struct lb_affinity_val *val;

	ipv6_addr_copy(&key.client_id.client_ip, &id->client_ip);

	val = map_lookup_elem(&LB6_AFFINITY_MAP, &key);
	if (val != NULL) {
		if (val->last_used + svc->affinity_timeout < now) {
			map_delete_elem(&LB6_AFFINITY_MAP, &key);
			return 0;
		}

		match.backend_id = val->backend_id;
		if (map_lookup_elem(&LB_AFFINITY_MATCH_MAP, &match) == NULL) {
			map_delete_elem(&LB6_AFFINITY_MAP, &key);
			return 0;
		}

		return val->backend_id;
	}

	return 0;
}

static __always_inline __u32
lb6_affinity_backend_id_by_addr(const struct lb6_service *svc,
				union lb6_affinity_client_id *id)
{
	return __lb6_affinity_backend_id(svc, false, id);
}

static __always_inline void
__lb6_update_affinity(const struct lb6_service *svc, bool netns_cookie,
		      union lb6_affinity_client_id *id, __u32 backend_id)
{
	__u32 now = bpf_ktime_get_sec();
	struct lb6_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
	};
	struct lb_affinity_val val = {
		.backend_id	= backend_id,
		.last_used	= now,
	};

	ipv6_addr_copy(&key.client_id.client_ip, &id->client_ip);

	map_update_elem(&LB6_AFFINITY_MAP, &key, &val, 0);
}

static __always_inline void
lb6_update_affinity_by_addr(const struct lb6_service *svc,
			    union lb6_affinity_client_id *id, __u32 backend_id)
{
	__lb6_update_affinity(svc, false, id, backend_id);
}

static __always_inline void
__lb6_delete_affinity(const struct lb6_service *svc, bool netns_cookie,
		      union lb6_affinity_client_id *id)
{
	struct lb6_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
	};

	ipv6_addr_copy(&key.client_id.client_ip, &id->client_ip);

	map_delete_elem(&LB6_AFFINITY_MAP, &key);
}

static __always_inline void
lb6_delete_affinity_by_addr(const struct lb6_service *svc,
			    union lb6_affinity_client_id *id)
{
	__lb6_delete_affinity(svc, false, id);
}
#endif /* ENABLE_SESSION_AFFINITY */

static __always_inline __u32
lb6_affinity_backend_id_by_netns(const struct lb6_service *svc __maybe_unused,
				 union lb6_affinity_client_id *id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY) && defined(BPF_HAVE_NETNS_COOKIE)
	return __lb6_affinity_backend_id(svc, true, id);
#else
	return 0;
#endif
}

static __always_inline void
lb6_update_affinity_by_netns(const struct lb6_service *svc __maybe_unused,
			     union lb6_affinity_client_id *id __maybe_unused,
			     __u32 backend_id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY) && defined(BPF_HAVE_NETNS_COOKIE)
	__lb6_update_affinity(svc, true, id, backend_id);
#endif
}

static __always_inline void
lb6_delete_affinity_by_netns(const struct lb6_service *svc __maybe_unused,
			     union lb6_affinity_client_id *id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY) && defined(BPF_HAVE_NETNS_COOKIE)
	__lb6_delete_affinity(svc, true, id);
#endif
}

static __always_inline int lb6_local(const void *map, struct __ctx_buff *ctx,
				     int l3_off, int l4_off,
				     struct csum_offset *csum_off,
				     struct lb6_key *key,
				     struct ipv6_ct_tuple *tuple,
				     const struct lb6_service *svc,
				     struct ct_state *state)
{
	__u32 monitor; // Deliberately ignored; regular CT will determine monitoring.
	union v6addr *addr;
	__u8 flags = tuple->flags;
	struct lb6_backend *backend;
	struct lb6_service *slave_svc;
	int slave;
	__u32 backend_id = 0;
	bool backend_from_affinity = false;
	int ret;
#ifdef ENABLE_SESSION_AFFINITY
	union lb6_affinity_client_id client_id;
	ipv6_addr_copy(&client_id.client_ip, &tuple->saddr);
#endif

	/* See lb4_local comments re svc endpoint lookup process */
	ret = ct_lookup6(map, tuple, ctx, l4_off, CT_SERVICE, state, &monitor);
	switch(ret) {
	case CT_NEW:
#ifdef ENABLE_SESSION_AFFINITY
		if (svc->affinity) {
			backend_id = lb6_affinity_backend_id_by_addr(svc, &client_id);
			if (backend_id != 0) {
				backend_from_affinity = true;

				backend = lb6_lookup_backend(ctx, backend_id);
				if (backend == NULL) {
					lb6_delete_affinity_by_addr(svc, &client_id);
					backend_id = 0;
				}
			}
		}
#endif
		if (backend_id == 0) {
			backend_from_affinity = false;

			slave = lb6_select_slave(svc->count);
			if ((slave_svc = lb6_lookup_slave(ctx, key, slave)) == NULL)
				goto drop_no_service;

			backend_id = slave_svc->backend_id;

			backend = lb6_lookup_backend(ctx, slave_svc->backend_id);
			if (backend == NULL)
				goto drop_no_service;
		}

		state->backend_id = backend_id;
		state->rev_nat_index = svc->rev_nat_index;

		ret = ct_create6(map, NULL, tuple, ctx, CT_SERVICE, state, false);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret)) {
			goto drop_no_service;
		}
		goto update_state;
	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		// See lb4_local comment
		if (state->rev_nat_index == 0) {
			state->rev_nat_index = svc->rev_nat_index;
			ct_update6_rev_nat_index(map, tuple, state);
		}
		break;
	default:
		goto drop_no_service;
	}

	// See lb4_local comment
	if (state->rev_nat_index != svc->rev_nat_index) {
#ifdef ENABLE_SESSION_AFFINITY
		if (svc->affinity) {
			backend_id = lb6_affinity_backend_id_by_addr(svc,
								     &client_id);
			backend_from_affinity = true;
		}
#endif
		if (backend_id == 0) {
			slave = lb6_select_slave(svc->count);
			if (!(slave_svc = lb6_lookup_slave(ctx, key, slave)))
				goto drop_no_service;
			backend_id = slave_svc->backend_id;
		}

		state->backend_id = backend_id;
		ct_update6_backend_id(map, tuple, state);
		state->rev_nat_index = svc->rev_nat_index;
		ct_update6_rev_nat_index(map, tuple, state);
	}
	/* If the lookup fails it means the user deleted the backend out from
	 * underneath us. To resolve this fall back to hash. If this is a TCP
	 * session we are likely to get a TCP RST.
	 */
	if (!(backend = lb6_lookup_backend(ctx, state->backend_id))) {
/* NOTE(brb): Can't enable the removal for newer kernels, as otherwise
 * the verifier hits 1mln insn limit. Hovewer, the removal of the affinity
 * in this case is just an optimization. */
#if defined(ENABLE_SESSION_AFFINITY) && !defined(HAVE_LARGE_INSN_LIMIT)
		if (backend_from_affinity)
			lb6_delete_affinity_by_addr(svc, &client_id);
#endif
		key->slave = 0;
		if (!(svc = lb6_lookup_service(key))) {
			goto drop_no_service;
		}
		slave = lb6_select_slave(svc->count);
		if (!(slave_svc = lb6_lookup_slave(ctx, key, slave))) {
			goto drop_no_service;
		}
		backend = lb6_lookup_backend(ctx, slave_svc->backend_id);
		if (backend == NULL) {
			goto drop_no_service;
		}
		state->backend_id = slave_svc->backend_id;
		ct_update6_backend_id(map, tuple, state);
	}

update_state:
	/* Restore flags so that SERVICE flag is only used in used when the
	 * service lookup happens and future lookups use EGRESS or INGRESS.
	 */
	tuple->flags = flags;
	ipv6_addr_copy(&tuple->daddr, &backend->address);
	addr = &tuple->daddr;
	state->rev_nat_index = svc->rev_nat_index;

#ifdef ENABLE_SESSION_AFFINITY
	if (svc->affinity)
		lb6_update_affinity_by_addr(svc, &client_id,
					    state->backend_id);
#endif
	return lb6_xlate(ctx, addr, tuple->nexthdr, l3_off, l4_off,
			 csum_off, key, backend);

drop_no_service:
	tuple->flags = flags;
	return DROP_NO_SERVICE;
}
#else
/* Stubs for v4-in-v6 socket cgroup hook case when only v4 is enabled to avoid
 * additional map management.
 */
static __always_inline
struct lb6_service *lb6_lookup_service(struct lb6_key *key __maybe_unused)
{
	return NULL;
}

static __always_inline
struct lb6_service *__lb6_lookup_slave(struct lb6_key *key __maybe_unused)
{
	return NULL;
}

static __always_inline struct lb6_backend *
__lb6_lookup_backend(__u16 backend_id __maybe_unused)
{
	return NULL;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int __lb4_rev_nat(struct __ctx_buff *ctx, int l3_off, int l4_off,
					 struct csum_offset *csum_off,
					 struct ipv4_ct_tuple *tuple, int flags,
					 const struct lb4_reverse_nat *nat,
					 const struct ct_state *ct_state)
{
	__be32 old_sip, new_sip, sum = 0;
	int ret;

	cilium_dbg_lb(ctx, DBG_LB4_REVERSE_NAT, nat->address, nat->port);

	if (nat->port) {
		ret = reverse_map_l4_port(ctx, tuple->nexthdr, nat->port, l4_off, csum_off);
		if (IS_ERR(ret))
			return ret;
	}

	if (flags & REV_NAT_F_TUPLE_SADDR) {
		old_sip = tuple->saddr;
		tuple->saddr = new_sip = nat->address;
	} else {
		ret = ctx_load_bytes(ctx, l3_off + offsetof(struct iphdr, saddr), &old_sip, 4);
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

		ret = ctx_load_bytes(ctx, l3_off + offsetof(struct iphdr, daddr), &old_dip, 4);
		if (IS_ERR(ret))
			return ret;

		cilium_dbg_lb(ctx, DBG_LB4_LOOPBACK_SNAT_REV, old_dip, old_sip);

		ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, daddr), &old_sip, 4, 0);
		if (IS_ERR(ret))
			return DROP_WRITE_ERROR;

		sum = csum_diff(&old_dip, 4, &old_sip, 4, 0);

		/* Update the tuple address which is representing the destination address */
		tuple->saddr = old_sip;
	}

        ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, saddr), &new_sip, 4, 0);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(&old_sip, 4, &new_sip, 4, sum);
	if (l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
		return DROP_CSUM_L3;

	if (csum_off->offset &&
	    csum_l4_replace(ctx, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}


/** Perform IPv4 reverse NAT based on reverse NAT index
 * @arg ctx		packet
 * @arg l3_off		offset to L3
 * @arg l4_off		offset to L4
 * @arg csum_off	offset to L4 checksum field
 * @arg csum_flags	checksum flags
 * @arg index		reverse NAT index
 * @arg tuple		tuple
 */
static __always_inline int lb4_rev_nat(struct __ctx_buff *ctx, int l3_off, int l4_off,
				       struct csum_offset *csum_off,
				       struct ct_state *ct_state,
				       struct ipv4_ct_tuple *tuple, int flags)
{
	struct lb4_reverse_nat *nat;

	cilium_dbg_lb(ctx, DBG_LB4_REVERSE_NAT_LOOKUP, ct_state->rev_nat_index, 0);
	nat = map_lookup_elem(&LB4_REVERSE_NAT_MAP, &ct_state->rev_nat_index);
	if (nat == NULL)
		return 0;

	return __lb4_rev_nat(ctx, l3_off, l4_off, csum_off, tuple, flags, nat,
			     ct_state);
}

/** Extract IPv4 LB key from packet
 * @arg ctx		Packet
 * @arg ip4		Pointer to L3 header
 * @arg l4_off		Offset to L4 header
 * @arg key		Pointer to store LB key in
 * @arg csum_off	Pointer to store L4 checksum field offset  in
 * @arg dir		Flow direction
 *
 * Returns:
 *   - CTX_ACT_OK on successful extraction
 *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)
 *   - Negative error code
 */
static __always_inline int lb4_extract_key(struct __ctx_buff *ctx __maybe_unused,
					   struct iphdr *ip4,
					   int l4_off __maybe_unused,
					   struct lb4_key *key,
					   struct csum_offset *csum_off,
					   int dir)
{
	// FIXME: set after adding support for different L4 protocols in LB
	key->proto = 0;
	key->address = (dir == CT_INGRESS) ? ip4->saddr : ip4->daddr;
	csum_l4_offset_and_flags(ip4->protocol, csum_off);

#ifdef LB_L4
	return extract_l4_port(ctx, ip4->protocol, l4_off, &key->dport, ip4);
#else
	return 0;
#endif
}

static __always_inline
struct lb4_service *lb4_lookup_service(struct lb4_key *key)
{
	key->slave = 0;
#ifdef LB_L4
	if (key->dport) {
		struct lb4_service *svc;

		/* FIXME: The verifier barks on these calls right now for some reason */
		/* cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_MASTER, key->address, key->dport); */
		svc = map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
		if (svc && svc->count != 0)
			return svc;

		key->dport = 0;
	}
#endif

#ifdef LB_L3
	if (1) {
		struct lb4_service *svc;

		/* FIXME: The verifier barks on these calls right now for some reason */
		/* cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_MASTER, key->address, key->dport); */
		svc = map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
		if (svc && svc->count != 0)
			return svc;
	}
#endif
	return NULL;
}

static __always_inline struct lb4_backend *__lb4_lookup_backend(__u16 backend_id)
{
	return map_lookup_elem(&LB4_BACKEND_MAP, &backend_id);
}

static __always_inline struct lb4_backend *
lb4_lookup_backend(struct __ctx_buff *ctx __maybe_unused, __u16 backend_id)
{
	struct lb4_backend *backend;

	backend = __lb4_lookup_backend(backend_id);
	if (!backend) {
		cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_BACKEND_FAIL, backend_id, 0);
	}

	return backend;
}

static __always_inline
struct lb4_service *__lb4_lookup_slave(struct lb4_key *key)
{
	return map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
}

static __always_inline
struct lb4_service *lb4_lookup_slave(struct __ctx_buff *ctx __maybe_unused,
				     struct lb4_key *key, __u16 slave)
{
	struct lb4_service *svc;

	key->slave = slave;
	cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_SLAVE, key->slave, key->dport);
	svc = __lb4_lookup_slave(key);
	if (svc != NULL) {
		return svc;
	}

	cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_SLAVE_V2_FAIL, key->slave, key->dport);

	return NULL;
}

static __always_inline int
lb4_xlate(struct __ctx_buff *ctx, __be32 *new_daddr, __be32 *new_saddr,
	     __be32 *old_saddr, __u8 nexthdr __maybe_unused,
	     int l3_off, int l4_off,
	     struct csum_offset *csum_off, struct lb4_key *key,
	     const struct lb4_backend *backend __maybe_unused)
{
	int ret;
	__be32 sum;

	ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, daddr), new_daddr, 4, 0);
	if (ret < 0)
		return DROP_WRITE_ERROR;

	sum = csum_diff(&key->address, 4, new_daddr, 4, 0);

	if (new_saddr && *new_saddr) {
		cilium_dbg_lb(ctx, DBG_LB4_LOOPBACK_SNAT, *old_saddr, *new_saddr);
		ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, saddr), new_saddr, 4, 0);
		if (ret < 0)
			return DROP_WRITE_ERROR;

		sum = csum_diff(old_saddr, 4, new_saddr, 4, sum);
	}

	if (l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
		return DROP_CSUM_L3;

	if (csum_off->offset) {
		if (csum_l4_replace(ctx, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

#ifdef LB_L4
	if (backend->port && key->dport != backend->port &&
	    (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)) {
		__be16 tmp = backend->port;
		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(ctx, l4_off, TCP_DPORT_OFF, csum_off, tmp, key->dport);
		if (IS_ERR(ret))
			return ret;
	}
#endif

	return CTX_ACT_OK;
}

#ifdef ENABLE_SESSION_AFFINITY
static __always_inline __u32
__lb4_affinity_backend_id(const struct lb4_service *svc, bool netns_cookie,
			  union lb4_affinity_client_id *id)
{
	__u32 now = bpf_ktime_get_sec();
	struct lb_affinity_match match = {
		.rev_nat_id	= svc->rev_nat_index,
	};
	struct lb4_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
		.client_id	= *id,
	};
	struct lb_affinity_val *val;

	val = map_lookup_elem(&LB4_AFFINITY_MAP, &key);
	if (val != NULL) {
		if (val->last_used + svc->affinity_timeout < now) {
			map_delete_elem(&LB4_AFFINITY_MAP, &key);
			return 0;
		}

		match.backend_id = val->backend_id;
		if (map_lookup_elem(&LB_AFFINITY_MATCH_MAP, &match) == NULL) {
			map_delete_elem(&LB4_AFFINITY_MAP, &key);
			return 0;
		}

		return val->backend_id;
	}

	return 0;
}

static __always_inline __u32
lb4_affinity_backend_id_by_addr(const struct lb4_service *svc,
				union lb4_affinity_client_id *id)
{
	return __lb4_affinity_backend_id(svc, false, id);
}

static __always_inline void
__lb4_update_affinity(const struct lb4_service *svc, bool netns_cookie,
		      union lb4_affinity_client_id *id, __u32 backend_id)
{
	__u32 now = bpf_ktime_get_sec();
	struct lb4_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
		.client_id	= *id,
	};
	struct lb_affinity_val val = {
		.backend_id	= backend_id,
		.last_used	= now,
	};

	map_update_elem(&LB4_AFFINITY_MAP, &key, &val, 0);
}

static __always_inline void
lb4_update_affinity_by_addr(const struct lb4_service *svc,
			    union lb4_affinity_client_id *id, __u32 backend_id)
{
	__lb4_update_affinity(svc, false, id, backend_id);
}

static __always_inline void
__lb4_delete_affinity(const struct lb4_service *svc, bool netns_cookie,
		      union lb4_affinity_client_id *id)
{
	struct lb4_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
		.client_id	= *id,
	};

	map_delete_elem(&LB4_AFFINITY_MAP, &key);
}

static __always_inline void
lb4_delete_affinity_by_addr(const struct lb4_service *svc,
			    union lb4_affinity_client_id *id)
{
	__lb4_delete_affinity(svc, false, id);
}
#endif /* ENABLE_SESSION_AFFINITY */

static __always_inline __u32
lb4_affinity_backend_id_by_netns(const struct lb4_service *svc __maybe_unused,
				 union lb4_affinity_client_id *id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY) && defined(BPF_HAVE_NETNS_COOKIE)
	return __lb4_affinity_backend_id(svc, true, id);
#else
	return 0;
#endif
}

static __always_inline void
lb4_update_affinity_by_netns(const struct lb4_service *svc __maybe_unused,
			     union lb4_affinity_client_id *id __maybe_unused,
			     __u32 backend_id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY) && defined(BPF_HAVE_NETNS_COOKIE)
	__lb4_update_affinity(svc, true, id, backend_id);
#endif
}

static __always_inline void
lb4_delete_affinity_by_netns(const struct lb4_service *svc __maybe_unused,
			     union lb4_affinity_client_id *id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY) && defined(BPF_HAVE_NETNS_COOKIE)
	__lb4_delete_affinity(svc, true, id);
#endif
}

static __always_inline int lb4_local(const void *map, struct __ctx_buff *ctx,
				     int l3_off, int l4_off,
				     struct csum_offset *csum_off,
				     struct lb4_key *key,
				     struct ipv4_ct_tuple *tuple,
				     const struct lb4_service *svc,
				     struct ct_state *state, __be32 saddr)
{
	__u32 monitor; // Deliberately ignored; regular CT will determine monitoring.
	__be32 new_saddr = 0, new_daddr;
	__u8 flags = tuple->flags;
	struct lb4_backend *backend;
	struct lb4_service *slave_svc;
	int slave;
	__u32 backend_id = 0;
	bool backend_from_affinity = false;
	int ret;
#ifdef ENABLE_SESSION_AFFINITY
	union lb4_affinity_client_id client_id = {
		.client_ip = saddr,
	};
#endif
	ret = ct_lookup4(map, tuple, ctx, l4_off, CT_SERVICE, state, &monitor);
	switch(ret) {
	case CT_NEW:
#ifdef ENABLE_SESSION_AFFINITY
		if (svc->affinity) {
			backend_id = lb4_affinity_backend_id_by_addr(svc, &client_id);
			if (backend_id != 0) {
				backend_from_affinity = true;

				backend = lb4_lookup_backend(ctx, backend_id);
				if (backend == NULL) {
					lb4_delete_affinity_by_addr(svc, &client_id);
					backend_id = 0;
				}
			}
		}
#endif
		if (backend_id == 0) {
			backend_from_affinity = false;

			/* No CT entry has been found, so select a svc endpoint */
			slave = lb4_select_slave(svc->count);
			if ((slave_svc = lb4_lookup_slave(ctx, key, slave)) == NULL)
				goto drop_no_service;

			backend_id = slave_svc->backend_id;

			backend = lb4_lookup_backend(ctx, backend_id);
			if (backend == NULL)
				goto drop_no_service;
		}

		state->backend_id = backend_id;
		state->rev_nat_index = svc->rev_nat_index;

		ret = ct_create4(map, NULL, tuple, ctx, CT_SERVICE, state, false);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret))
			goto drop_no_service;
		goto update_state;
	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		// For backward-compatibility we need to update reverse NAT index
		// in the CT_SERVICE entry for old connections, as later in the code
		// we check whether the right backend is used. Having it set to 0
		// would trigger a new backend selection which would in many cases
		// would pick a different backend.
		if (unlikely(state->rev_nat_index == 0)) {
			state->rev_nat_index = svc->rev_nat_index;
			ct_update4_rev_nat_index(map, tuple, state);
		}
		break;
	default:
		goto drop_no_service;
	}

	// If the CT_SERVICE entry is from a non-related connection (e.g.
	// endpoint has been removed, but its CT entries were not (it is
	// totally possible due to the bug in DumpReliablyWithCallback)),
	// then a wrong (=from unrelated service) backend can be selected.
	// To avoid this, check that reverse NAT indices match. If not,
	// select a new backend.
	if (state->rev_nat_index != svc->rev_nat_index) {
#ifdef ENABLE_SESSION_AFFINITY
		if (svc->affinity) {
			backend_id = lb4_affinity_backend_id_by_addr(svc,
								     &client_id);
			backend_from_affinity = true;
		}
#endif
		if (backend_id == 0) {
			slave = lb4_select_slave(svc->count);
			if (!(slave_svc = lb4_lookup_slave(ctx, key, slave)))
				goto drop_no_service;

			backend_id = slave_svc->backend_id;
		}

		state->backend_id = backend_id;
		ct_update4_backend_id(map, tuple, state);
		state->rev_nat_index = svc->rev_nat_index;
		ct_update4_rev_nat_index(map, tuple, state);
	}
	/* If the lookup fails it means the user deleted the backend out from
	 * underneath us. To resolve this fall back to hash. If this is a TCP
	 * session we are likely to get a TCP RST.
	 */
	if (!(backend = lb4_lookup_backend(ctx, state->backend_id))) {
#ifdef ENABLE_SESSION_AFFINITY
		if (backend_from_affinity)
			lb4_delete_affinity_by_addr(svc, &client_id);
#endif
		key->slave = 0;
		if (!(svc = lb4_lookup_service(key))) {
			goto drop_no_service;
		}
		slave = lb4_select_slave(svc->count);
		if (!(slave_svc = lb4_lookup_slave(ctx, key, slave))) {
			goto drop_no_service;
		}
		backend = lb4_lookup_backend(ctx, slave_svc->backend_id);
		if (backend == NULL) {
			goto drop_no_service;
		}
		state->backend_id = slave_svc->backend_id;
		ct_update4_backend_id(map, tuple, state);
	}

update_state:
	/* Restore flags so that SERVICE flag is only used in used when the
	 * service lookup happens and future lookups use EGRESS or INGRESS.
	 */
	tuple->flags = flags;
	state->rev_nat_index = svc->rev_nat_index;
	state->addr = new_daddr = backend->address;

#ifdef ENABLE_SESSION_AFFINITY
	if (svc->affinity)
		lb4_update_affinity_by_addr(svc, &client_id,
					    state->backend_id);
#endif

#ifndef DISABLE_LOOPBACK_LB
	/* Special loopback case: The origin endpoint has transmitted to a
	 * service which is being translated back to the source. This would
	 * result in a packet with identical source and destination address.
	 * Linux considers such packets as martian source and will drop unless
	 * received on a loopback device. Perform NAT on the source address
	 * to make it appear from an outside address.
	 */
	if (saddr == backend->address) {
		new_saddr = IPV4_LOOPBACK;
		state->loopback = 1;
		state->addr = new_saddr;
		state->svc_addr = saddr;
	}
#endif
	if (!state->loopback)
		tuple->daddr = backend->address;

	return lb4_xlate(ctx, &new_daddr, &new_saddr, &saddr,
			 tuple->nexthdr, l3_off, l4_off, csum_off, key,
			 backend);
drop_no_service:
		tuple->flags = flags;
		return DROP_NO_SERVICE;
}
#endif /* ENABLE_IPV4 */
#endif /* __LB_H_ */
