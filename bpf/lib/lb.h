/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LB_H_
#define __LB_H_

#include "csum.h"
#include "conntrack.h"
#include "ipv4.h"
#include "hash.h"
#include "ids.h"
#include "nat_46x64.h"

#ifdef ENABLE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct lb6_reverse_nat);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB6_REVERSE_NAT_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb6_key);
	__type(value, struct lb6_service);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_SERVICE_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB6_SERVICES_MAP_V2 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct lb6_backend);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB6_BACKEND_MAP_V2 __section_maps_btf;

#ifdef ENABLE_SESSION_AFFINITY
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct lb6_affinity_key);
	__type(value, struct lb_affinity_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES);
} LB6_AFFINITY_MAP __section_maps_btf;
#endif

#ifdef ENABLE_SRC_RANGE_CHECK
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lb6_src_range_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB6_SRC_RANGE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} LB6_SRC_RANGE_MAP __section_maps_btf;
#endif

#ifdef ENABLE_HEALTH_CHECK
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __sock_cookie);
	__type(value, struct lb6_health);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES);
} LB6_HEALTH_MAP __section_maps_btf;
#endif

#if LB_SELECTION == LB_SELECTION_MAGLEV
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u16);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_MAGLEV_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	/* Maglev inner map definition */
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__type(key, __u32);
		__uint(value_size, sizeof(__u32) * LB_MAGLEV_LUT_SIZE);
		__uint(max_entries, 1);
	});
} LB6_MAGLEV_MAP_OUTER __section_maps_btf;
#endif /* LB_SELECTION == LB_SELECTION_MAGLEV */
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct lb4_reverse_nat);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB4_REVERSE_NAT_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb4_key);
	__type(value, struct lb4_service);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_SERVICE_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB4_SERVICES_MAP_V2 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct lb4_backend);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB4_BACKEND_MAP_V2 __section_maps_btf;

#ifdef ENABLE_SESSION_AFFINITY
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct lb4_affinity_key);
	__type(value, struct lb_affinity_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES);
} LB4_AFFINITY_MAP __section_maps_btf;
#endif

#ifdef ENABLE_SRC_RANGE_CHECK
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lb4_src_range_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB4_SRC_RANGE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} LB4_SRC_RANGE_MAP __section_maps_btf;
#endif

#ifdef ENABLE_HEALTH_CHECK
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __sock_cookie);
	__type(value, struct lb4_health);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES);
} LB4_HEALTH_MAP __section_maps_btf;
#endif

#if LB_SELECTION == LB_SELECTION_MAGLEV
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u16);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_MAGLEV_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	/* Maglev inner map definition */
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__type(key, __u32);
		__uint(value_size, sizeof(__u32) * LB_MAGLEV_LUT_SIZE);
		__uint(max_entries, 1);
	});
} LB4_MAGLEV_MAP_OUTER __section_maps_btf;
#endif /* LB_SELECTION == LB_SELECTION_MAGLEV */
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_SESSION_AFFINITY
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb_affinity_match);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB_AFFINITY_MATCH_MAP __section_maps_btf;
#endif

#define REV_NAT_F_TUPLE_SADDR	1
#ifndef DSR_XLATE_MODE
# define DSR_XLATE_MODE		0
# define DSR_XLATE_FRONTEND	1
#endif
#ifdef LB_DEBUG
#define cilium_dbg_lb cilium_dbg
#else
#define cilium_dbg_lb(a, b, c, d)
#endif

static __always_inline
bool lb4_svc_is_loadbalancer(const struct lb4_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_LOADBALANCER;
}

static __always_inline
bool lb6_svc_is_loadbalancer(const struct lb6_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_LOADBALANCER;
}

static __always_inline
bool lb4_svc_is_nodeport(const struct lb4_service *svc __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	return svc->flags & SVC_FLAG_NODEPORT;
#else
	return false;
#endif /* ENABLE_NODEPORT */
}

static __always_inline
bool lb6_svc_is_nodeport(const struct lb6_service *svc __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	return svc->flags & SVC_FLAG_NODEPORT;
#else
	return false;
#endif /* ENABLE_NODEPORT */
}

static __always_inline
bool lb4_svc_is_external_ip(const struct lb4_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_EXTERNAL_IP;
}

static __always_inline
bool lb6_svc_is_external_ip(const struct lb6_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_EXTERNAL_IP;
}

static __always_inline
bool lb4_svc_is_hostport(const struct lb4_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_HOSTPORT;
}

static __always_inline
bool lb6_svc_is_hostport(const struct lb6_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_HOSTPORT;
}

static __always_inline
bool lb4_svc_has_src_range_check(const struct lb4_service *svc __maybe_unused)
{
#ifdef ENABLE_SRC_RANGE_CHECK
	return svc->flags & SVC_FLAG_SOURCE_RANGE;
#else
	return false;
#endif /* ENABLE_SRC_RANGE_CHECK */
}

static __always_inline
bool lb6_svc_has_src_range_check(const struct lb6_service *svc __maybe_unused)
{
#ifdef ENABLE_SRC_RANGE_CHECK
	return svc->flags & SVC_FLAG_SOURCE_RANGE;
#else
	return false;
#endif /* ENABLE_SRC_RANGE_CHECK */
}

static __always_inline bool lb_skip_l4_dnat(void)
{
	return DSR_XLATE_MODE == DSR_XLATE_FRONTEND;
}

static __always_inline
bool lb4_svc_is_local_scope(const struct lb4_service *svc)
{
	return svc->flags & SVC_FLAG_LOCAL_SCOPE;
}

static __always_inline
bool lb6_svc_is_local_scope(const struct lb6_service *svc)
{
	return svc->flags & SVC_FLAG_LOCAL_SCOPE;
}

static __always_inline
bool lb4_svc_is_affinity(const struct lb4_service *svc)
{
	return svc->flags & SVC_FLAG_AFFINITY;
}

static __always_inline
bool lb6_svc_is_affinity(const struct lb6_service *svc)
{
	return svc->flags & SVC_FLAG_AFFINITY;
}

static __always_inline bool __lb_svc_is_routable(__u8 flags)
{
	return (flags & SVC_FLAG_ROUTABLE) != 0;
}

static __always_inline
bool lb4_svc_is_routable(const struct lb4_service *svc)
{
	return __lb_svc_is_routable(svc->flags);
}

static __always_inline
bool lb6_svc_is_routable(const struct lb6_service *svc)
{
	return __lb_svc_is_routable(svc->flags);
}

static __always_inline
bool lb4_svc_is_localredirect(const struct lb4_service *svc)
{
	return svc->flags2 & SVC_FLAG_LOCALREDIRECT;
}

static __always_inline
bool lb4_svc_is_l7loadbalancer(const struct lb4_service *svc __maybe_unused)
{
#ifdef ENABLE_L7_LB
	return svc->flags2 & SVC_FLAG_L7LOADBALANCER;
#else
	return false;
#endif
}

static __always_inline
bool lb6_svc_is_l7loadbalancer(const struct lb6_service *svc __maybe_unused)
{
#ifdef ENABLE_L7_LB
	return svc->flags2 & SVC_FLAG_L7LOADBALANCER;
#else
	return false;
#endif
}

static __always_inline int extract_l4_port(struct __ctx_buff *ctx, __u8 nexthdr,
					   int l4_off,
					   enum ct_dir dir __maybe_unused,
					   __be16 *port,
					   __maybe_unused struct iphdr *ip4)
{
	int ret;

	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_IPV4_FRAGMENTS
		if (ip4) {
			struct ipv4_frag_l4ports ports = { };

			ret = ipv4_handle_fragmentation(ctx, ip4, l4_off,
							dir, &ports, NULL);
			if (IS_ERR(ret))
				return ret;
			*port = ports.dport;
			break;
		}
#endif
		/* Port offsets for UDP and TCP are the same */
		ret = l4_load_port(ctx, l4_off + TCP_DPORT_OFF, port);
		if (IS_ERR(ret))
			return ret;
		break;

	case IPPROTO_ICMPV6:
	case IPPROTO_ICMP:
		/* No need to perform a service lookup for ICMP packets */
		return DROP_NO_SERVICE;

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
		return CTX_ACT_OK;

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
					   enum ct_dir dir)
{
	union v6addr *addr;
	/* FIXME(brb): set after adding support for different L4 protocols in LB */
	key->proto = 0;
	addr = (dir == CT_INGRESS) ? &tuple->saddr : &tuple->daddr;
	ipv6_addr_copy(&key->address, addr);
	csum_l4_offset_and_flags(tuple->nexthdr, csum_off);

	return extract_l4_port(ctx, tuple->nexthdr, l4_off, dir, &key->dport,
			       NULL);
}

static __always_inline
bool lb6_src_range_ok(const struct lb6_service *svc __maybe_unused,
		      const union v6addr *saddr __maybe_unused)
{
#ifdef ENABLE_SRC_RANGE_CHECK
	struct lb6_src_range_key key;

	if (!lb6_svc_has_src_range_check(svc))
		return true;

	key = (typeof(key)) {
		.lpm_key = { SRC_RANGE_STATIC_PREFIX(key), {} },
		.rev_nat_id = svc->rev_nat_index,
		.addr = *saddr,
	};

	if (map_lookup_elem(&LB6_SRC_RANGE_MAP, &key))
		return true;

	return false;
#else
	return true;
#endif /* ENABLE_SRC_RANGE_CHECK */
}

static __always_inline bool
lb6_to_lb4_service(const struct lb6_service *svc __maybe_unused)
{
#ifdef ENABLE_NAT_46X64
	return svc->flags2 & SVC_FLAG_NAT_46X64;
#else
	return false;
#endif
}

static __always_inline
struct lb6_service *lb6_lookup_service(struct lb6_key *key,
				       const bool scope_switch)
{
	struct lb6_service *svc;

	key->scope = LB_LOOKUP_SCOPE_EXT;
	key->backend_slot = 0;
	svc = map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
	if (svc) {
		if (!scope_switch || !lb6_svc_is_local_scope(svc))
			/* Packets for L7 LB are redirected even when there are no backends. */
			return (svc->count || lb6_svc_is_l7loadbalancer(svc)) ? svc : NULL;
		key->scope = LB_LOOKUP_SCOPE_INT;
		svc = map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
		if (svc && (svc->count || lb6_svc_is_l7loadbalancer(svc)))
			return svc;
	}

	return NULL;
}

static __always_inline struct lb6_backend *__lb6_lookup_backend(__u32 backend_id)
{
	return map_lookup_elem(&LB6_BACKEND_MAP_V2, &backend_id);
}

static __always_inline struct lb6_backend *
lb6_lookup_backend(struct __ctx_buff *ctx __maybe_unused, __u32 backend_id)
{
	struct lb6_backend *backend;

	backend = __lb6_lookup_backend(backend_id);
	if (!backend)
		cilium_dbg_lb(ctx, DBG_LB6_LOOKUP_BACKEND_FAIL, backend_id, 0);

	return backend;
}

static __always_inline
struct lb6_service *__lb6_lookup_backend_slot(struct lb6_key *key)
{
	return map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
}

static __always_inline
struct lb6_service *lb6_lookup_backend_slot(struct __ctx_buff *ctx __maybe_unused,
					    struct lb6_key *key, __u16 slot)
{
	struct lb6_service *svc;

	key->backend_slot = slot;
	cilium_dbg_lb(ctx, DBG_LB6_LOOKUP_BACKEND_SLOT, key->backend_slot, key->dport);
	svc = __lb6_lookup_backend_slot(key);
	if (svc)
		return svc;

	cilium_dbg_lb(ctx, DBG_LB6_LOOKUP_BACKEND_SLOT_V2_FAIL, key->backend_slot, key->dport);

	return NULL;
}

/* Backend slot 0 is always reserved for the service frontend. */
#if LB_SELECTION == LB_SELECTION_RANDOM
static __always_inline __u32
lb6_select_backend_id(struct __ctx_buff *ctx,
		      struct lb6_key *key,
		      const struct ipv6_ct_tuple *tuple __maybe_unused,
		      const struct lb6_service *svc)
{
	__u16 slot = (get_prandom_u32() % svc->count) + 1;
	struct lb6_service *be = lb6_lookup_backend_slot(ctx, key, slot);

	return be ? be->backend_id : 0;
}
#elif LB_SELECTION == LB_SELECTION_MAGLEV
static __always_inline __u32
lb6_select_backend_id(struct __ctx_buff *ctx __maybe_unused,
		      struct lb6_key *key __maybe_unused,
		      const struct ipv6_ct_tuple *tuple,
		      const struct lb6_service *svc)
{
	__u32 zero = 0, index = svc->rev_nat_index;
	__u32 *backend_ids;
	void *maglev_lut;

	maglev_lut = map_lookup_elem(&LB6_MAGLEV_MAP_OUTER, &index);
	if (unlikely(!maglev_lut))
		return 0;

	backend_ids = map_lookup_elem(maglev_lut, &zero);
	if (unlikely(!backend_ids))
		return 0;

	index = hash_from_tuple_v6(tuple) % LB_MAGLEV_LUT_SIZE;
        return map_array_get_32(backend_ids, index, (LB_MAGLEV_LUT_SIZE - 1) << 2);
}
#else
# error "Invalid load balancer backend selection algorithm!"
#endif /* LB_SELECTION */

static __always_inline int lb6_xlate(struct __ctx_buff *ctx,
				     const union v6addr *new_dst, __u8 nexthdr,
				     int l3_off, int l4_off,
				     struct csum_offset *csum_off,
				     const struct lb6_key *key,
				     const struct lb6_backend *backend,
				     const bool skip_l3_xlate)
{
	if (skip_l3_xlate)
		goto l4_xlate;

	ipv6_store_daddr(ctx, new_dst->addr, l3_off);
	if (csum_off) {
		__be32 sum = csum_diff(key->address.addr, 16, new_dst->addr,
				       16, 0);

		if (csum_l4_replace(ctx, l4_off, csum_off, 0, sum,
				    BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

l4_xlate:
	if (likely(backend->port) && key->dport != backend->port &&
	    (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)) {
		__be16 tmp = backend->port;
		int ret;

		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(ctx, l4_off, TCP_DPORT_OFF, csum_off,
				     tmp, key->dport);
		if (IS_ERR(ret))
			return ret;
	}

	return CTX_ACT_OK;
}

#ifdef ENABLE_SESSION_AFFINITY
static __always_inline __u32
__lb6_affinity_backend_id(const struct lb6_service *svc, bool netns_cookie,
			  union lb6_affinity_client_id *id)
{
	struct lb6_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
	};
	struct lb_affinity_val *val;

	ipv6_addr_copy(&key.client_id.client_ip, &id->client_ip);

	val = map_lookup_elem(&LB6_AFFINITY_MAP, &key);
	if (val != NULL) {
		__u32 now = bpf_mono_now();
		struct lb_affinity_match match = {
			.rev_nat_id	= svc->rev_nat_index,
			.backend_id	= val->backend_id,
		};

		if (READ_ONCE(val->last_used) +
		    bpf_sec_to_mono(svc->affinity_timeout) <= now) {
			map_delete_elem(&LB6_AFFINITY_MAP, &key);
			return 0;
		}

		if (!map_lookup_elem(&LB_AFFINITY_MATCH_MAP, &match)) {
			map_delete_elem(&LB6_AFFINITY_MAP, &key);
			return 0;
		}

		WRITE_ONCE(val->last_used, now);
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
	__u32 now = bpf_mono_now();
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
#endif /* ENABLE_SESSION_AFFINITY */

static __always_inline __u32
lb6_affinity_backend_id_by_netns(const struct lb6_service *svc __maybe_unused,
				 union lb6_affinity_client_id *id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY)
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
#if defined(ENABLE_SESSION_AFFINITY)
	__lb6_update_affinity(svc, true, id, backend_id);
#endif
}

static __always_inline int
lb6_to_lb4(struct __ctx_buff *ctx __maybe_unused,
	   const struct ipv6hdr *ip6 __maybe_unused)
{
#ifdef ENABLE_NAT_46X64
	__be32 src4, dst4;

	build_v4_from_v6((const union v6addr *)&ip6->saddr, &src4);
	build_v4_from_v6((const union v6addr *)&ip6->daddr, &dst4);

	return ipv6_to_ipv4(ctx, src4, dst4);
#else
	return DROP_NAT_46X64_DISABLED;
#endif
}

static __always_inline int lb6_local(const void *map, struct __ctx_buff *ctx,
				     int l3_off, int l4_off,
				     struct csum_offset *csum_off,
				     struct lb6_key *key,
				     struct ipv6_ct_tuple *tuple,
				     const struct lb6_service *svc,
				     struct ct_state *state,
				     const bool skip_l3_xlate)
{
	__u32 monitor; /* Deliberately ignored; regular CT will determine monitoring. */
	union v6addr *addr;
	__u8 flags = tuple->flags;
	struct lb6_backend *backend;
	__u32 backend_id = 0;
	int ret;
#ifdef ENABLE_SESSION_AFFINITY
	union lb6_affinity_client_id client_id;

	ipv6_addr_copy(&client_id.client_ip, &tuple->saddr);
#endif

	/* See lb4_local comments re svc endpoint lookup process */
	ret = ct_lookup6(map, tuple, ctx, l4_off, CT_SERVICE, state, &monitor);
	switch (ret) {
	case CT_NEW:
#ifdef ENABLE_SESSION_AFFINITY
		if (lb6_svc_is_affinity(svc)) {
			backend_id = lb6_affinity_backend_id_by_addr(svc, &client_id);
			if (backend_id != 0) {
				backend = lb6_lookup_backend(ctx, backend_id);
				if (backend == NULL)
					backend_id = 0;
			}
		}
#endif
		if (backend_id == 0) {
			backend_id = lb6_select_backend_id(ctx, key, tuple, svc);
			backend = lb6_lookup_backend(ctx, backend_id);
			if (backend == NULL)
				goto drop_no_service;
		}

		state->backend_id = backend_id;
		state->rev_nat_index = svc->rev_nat_index;

		ret = ct_create6(map, NULL, tuple, ctx, CT_SERVICE, state, false, false);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret))
			goto drop_no_service;
		goto update_state;
	case CT_REOPENED:
	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		/* See lb4_local comment */
		if (state->rev_nat_index == 0) {
			state->rev_nat_index = svc->rev_nat_index;
			ct_update6_rev_nat_index(map, tuple, state);
		}
		break;
	default:
		goto drop_no_service;
	}

	/* See lb4_local comment */
	if (state->rev_nat_index != svc->rev_nat_index) {
#ifdef ENABLE_SESSION_AFFINITY
		if (lb6_svc_is_affinity(svc))
			backend_id = lb6_affinity_backend_id_by_addr(svc,
								     &client_id);
#endif
		if (!backend_id) {
			backend_id = lb6_select_backend_id(ctx, key, tuple, svc);
			if (!backend_id)
				goto drop_no_service;
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
	backend = lb6_lookup_backend(ctx, state->backend_id);
	if (!backend) {
		key->backend_slot = 0;
		svc = lb6_lookup_service(key, false);
		if (!svc)
			goto drop_no_service;
		backend_id = lb6_select_backend_id(ctx, key, tuple, svc);
		backend = lb6_lookup_backend(ctx, backend_id);
		if (!backend)
			goto drop_no_service;
		state->backend_id = backend_id;
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
	if (lb6_svc_is_affinity(svc))
		lb6_update_affinity_by_addr(svc, &client_id,
					    state->backend_id);
#endif
	return lb_skip_l4_dnat() ? CTX_ACT_OK :
	       lb6_xlate(ctx, addr, tuple->nexthdr, l3_off, l4_off,
			 csum_off, key, backend, skip_l3_xlate);
drop_no_service:
	tuple->flags = flags;
	return DROP_NO_SERVICE;
}

/* lb6_ctx_store_state() stores per packet load balancing state to be picked
 * up on the continuation tail call.
 * Note that the IP headers are already xlated and the tuple is re-initialized
 * from the xlated headers before restoring state.
 * NOTE: if lb_skip_l4_dnat() this is not the case as xlate is skipped. We
 * lose the updated tuple daddr in that case.
 */
static __always_inline void lb6_ctx_store_state(struct __ctx_buff *ctx,
						const struct ct_state *state,
					       __u16 proxy_port)
{
	ctx_store_meta(ctx, CB_PROXY_MAGIC, (__u32)proxy_port << 16);
	ctx_store_meta(ctx, CB_BACKEND_ID, state->backend_id);
	ctx_store_meta(ctx, CB_CT_STATE, (__u32)state->rev_nat_index);
}

/* lb6_ctx_restore_state() restores per packet load balancing state from the
 * previous tail call.
 * tuple->flags does not need to be restored, as it will be reinitialized from
 * the packet.
 */
static __always_inline void lb6_ctx_restore_state(struct __ctx_buff *ctx,
						  struct ct_state *state,
						 __u16 *proxy_port)
{
	state->rev_nat_index = (__u16)ctx_load_meta(ctx, CB_CT_STATE);
	/* Clear to not leak state to later stages of the datapath. */
	ctx_store_meta(ctx, CB_CT_STATE, 0);

	/* No loopback support for IPv6, see lb6_local() above. */

	state->backend_id = ctx_load_meta(ctx, CB_BACKEND_ID);
	/* Must clear to avoid policy bypass as CB_BACKEND_ID aliases CB_POLICY. */
	ctx_store_meta(ctx, CB_BACKEND_ID, 0);

	*proxy_port = ctx_load_meta(ctx, CB_PROXY_MAGIC) >> 16;
	ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);
}

#else

/* Stubs for v4-in-v6 socket cgroup hook case when only v4 is enabled to avoid
 * additional map management.
 */
static __always_inline
struct lb6_service *lb6_lookup_service(struct lb6_key *key __maybe_unused,
				       const bool scope_switch __maybe_unused)
{
	return NULL;
}

static __always_inline
struct lb6_service *__lb6_lookup_backend_slot(struct lb6_key *key __maybe_unused)
{
	return NULL;
}

static __always_inline struct lb6_backend *
__lb6_lookup_backend(__u16 backend_id __maybe_unused)
{
	return NULL;
}

static __always_inline bool
lb6_to_lb4_service(const struct lb6_service *svc __maybe_unused)
{
	return false;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int __lb4_rev_nat(struct __ctx_buff *ctx, int l3_off, int l4_off,
					 struct csum_offset *csum_off,
					 struct ipv4_ct_tuple *tuple, int flags,
					 const struct lb4_reverse_nat *nat,
					 const struct ct_state *ct_state, bool has_l4_header)
{
	__be32 old_sip, new_sip, sum = 0;
	int ret;

	cilium_dbg_lb(ctx, DBG_LB4_REVERSE_NAT, nat->address, nat->port);

	if (nat->port && has_l4_header) {
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
		 * address the new destination address.
		 */
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

	ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, saddr),
			      &new_sip, 4, 0);
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
				       struct ipv4_ct_tuple *tuple, int flags, bool has_l4_header)
{
	struct lb4_reverse_nat *nat;

	cilium_dbg_lb(ctx, DBG_LB4_REVERSE_NAT_LOOKUP, ct_state->rev_nat_index, 0);
	nat = map_lookup_elem(&LB4_REVERSE_NAT_MAP, &ct_state->rev_nat_index);
	if (nat == NULL)
		return 0;

	return __lb4_rev_nat(ctx, l3_off, l4_off, csum_off, tuple, flags, nat,
			     ct_state, has_l4_header);
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
					   enum ct_dir dir)
{
	/* FIXME: set after adding support for different L4 protocols in LB */
	key->proto = 0;
	key->address = (dir == CT_INGRESS) ? ip4->saddr : ip4->daddr;
	if (ipv4_has_l4_header(ip4))
		csum_l4_offset_and_flags(ip4->protocol, csum_off);

	return extract_l4_port(ctx, ip4->protocol, l4_off, dir, &key->dport, ip4);
}

static __always_inline
bool lb4_src_range_ok(const struct lb4_service *svc __maybe_unused,
		      __u32 saddr __maybe_unused)
{
#ifdef ENABLE_SRC_RANGE_CHECK
	struct lb4_src_range_key key;

	if (!lb4_svc_has_src_range_check(svc))
		return true;

	key = (typeof(key)) {
		.lpm_key = { SRC_RANGE_STATIC_PREFIX(key), {} },
		.rev_nat_id = svc->rev_nat_index,
		.addr = saddr,
	};

	if (map_lookup_elem(&LB4_SRC_RANGE_MAP, &key))
		return true;

	return false;
#else
	return true;
#endif /* ENABLE_SRC_RANGE_CHECK */
}

static __always_inline int
lb4_populate_ports(struct __ctx_buff *ctx, struct ipv4_ct_tuple *tuple, int off)
{
	if (tuple->nexthdr == IPPROTO_TCP ||
	    tuple->nexthdr == IPPROTO_UDP) {
		struct {
			__be16 sport;
			__be16 dport;
		} l4hdr;
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return -EFAULT;
		tuple->sport = l4hdr.sport;
		tuple->dport = l4hdr.dport;
		return 0;
	}
	return -ENOTSUP;
}

static __always_inline bool
lb4_to_lb6_service(const struct lb4_service *svc __maybe_unused)
{
#ifdef ENABLE_NAT_46X64
	return svc->flags2 & SVC_FLAG_NAT_46X64;
#else
	return false;
#endif
}

static __always_inline
struct lb4_service *lb4_lookup_service(struct lb4_key *key,
				       const bool scope_switch)
{
	struct lb4_service *svc;

	key->scope = LB_LOOKUP_SCOPE_EXT;
	key->backend_slot = 0;
	svc = map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
	if (svc) {
		if (!scope_switch || !lb4_svc_is_local_scope(svc))
			/* Packets for L7 LB are redirected even when there are no backends. */
			return (svc->count || lb4_to_lb6_service(svc) ||
				lb4_svc_is_l7loadbalancer(svc)) ? svc : NULL;
		key->scope = LB_LOOKUP_SCOPE_INT;
		svc = map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
		if (svc && (svc->count || lb4_svc_is_l7loadbalancer(svc)))
			return svc;
	}

	return NULL;
}

static __always_inline struct lb4_backend *__lb4_lookup_backend(__u32 backend_id)
{
	return map_lookup_elem(&LB4_BACKEND_MAP_V2, &backend_id);
}

static __always_inline struct lb4_backend *
lb4_lookup_backend(struct __ctx_buff *ctx __maybe_unused, __u32 backend_id)
{
	struct lb4_backend *backend;

	backend = __lb4_lookup_backend(backend_id);
	if (!backend)
		cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_BACKEND_FAIL, backend_id, 0);

	return backend;
}

static __always_inline
struct lb4_service *__lb4_lookup_backend_slot(struct lb4_key *key)
{
	return map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
}

static __always_inline
struct lb4_service *lb4_lookup_backend_slot(struct __ctx_buff *ctx __maybe_unused,
					    struct lb4_key *key, __u16 slot)
{
	struct lb4_service *svc;

	key->backend_slot = slot;
	cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_BACKEND_SLOT, key->backend_slot, key->dport);
	svc = __lb4_lookup_backend_slot(key);
	if (svc)
		return svc;

	cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_BACKEND_SLOT_V2_FAIL, key->backend_slot, key->dport);

	return NULL;
}

/* Backend slot 0 is always reserved for the service frontend. */
#if LB_SELECTION == LB_SELECTION_RANDOM
static __always_inline __u32
lb4_select_backend_id(struct __ctx_buff *ctx,
		      struct lb4_key *key,
		      const struct ipv4_ct_tuple *tuple __maybe_unused,
		      const struct lb4_service *svc)
{
	__u16 slot = (get_prandom_u32() % svc->count) + 1;
	struct lb4_service *be = lb4_lookup_backend_slot(ctx, key, slot);

	return be ? be->backend_id : 0;
}
#elif LB_SELECTION == LB_SELECTION_MAGLEV
static __always_inline __u32
lb4_select_backend_id(struct __ctx_buff *ctx __maybe_unused,
		      struct lb4_key *key __maybe_unused,
		      const struct ipv4_ct_tuple *tuple,
		      const struct lb4_service *svc)
{
	__u32 zero = 0, index = svc->rev_nat_index;
	__u32 *backend_ids;
	void *maglev_lut;

	maglev_lut = map_lookup_elem(&LB4_MAGLEV_MAP_OUTER, &index);
	if (unlikely(!maglev_lut))
		return 0;

	backend_ids = map_lookup_elem(maglev_lut, &zero);
	if (unlikely(!backend_ids))
		return 0;

	index = hash_from_tuple_v4(tuple) % LB_MAGLEV_LUT_SIZE;
        return map_array_get_32(backend_ids, index, (LB_MAGLEV_LUT_SIZE - 1) << 2);
}
#else
# error "Invalid load balancer backend selection algorithm!"
#endif /* LB_SELECTION */

static __always_inline int
lb4_xlate(struct __ctx_buff *ctx, __be32 *new_daddr, __be32 *new_saddr __maybe_unused,
	  __be32 *old_saddr __maybe_unused, __u8 nexthdr __maybe_unused, int l3_off,
	  int l4_off, struct csum_offset *csum_off, struct lb4_key *key,
	  const struct lb4_backend *backend __maybe_unused, bool has_l4_header,
	  const bool skip_l3_xlate)
{
	__be32 sum;
	int ret;

	if (skip_l3_xlate)
		goto l4_xlate;

	ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, daddr),
			      new_daddr, 4, 0);
	if (ret < 0)
		return DROP_WRITE_ERROR;

	sum = csum_diff(&key->address, 4, new_daddr, 4, 0);
#ifndef DISABLE_LOOPBACK_LB
	if (new_saddr && *new_saddr) {
		cilium_dbg_lb(ctx, DBG_LB4_LOOPBACK_SNAT, *old_saddr, *new_saddr);

		ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, saddr),
				      new_saddr, 4, 0);
		if (ret < 0)
			return DROP_WRITE_ERROR;

		sum = csum_diff(old_saddr, 4, new_saddr, 4, sum);
	}
#endif /* DISABLE_LOOPBACK_LB */
	if (l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	if (csum_off->offset) {
		if (csum_l4_replace(ctx, l4_off, csum_off, 0, sum,
				    BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

l4_xlate:
	if (likely(backend->port) && key->dport != backend->port &&
	    (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP) &&
	    has_l4_header) {
		__be16 tmp = backend->port;

		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(ctx, l4_off, TCP_DPORT_OFF, csum_off,
				     tmp, key->dport);
		if (IS_ERR(ret))
			return ret;
	}

	return CTX_ACT_OK;
}

#ifdef ENABLE_SESSION_AFFINITY
static __always_inline __u32
__lb4_affinity_backend_id(const struct lb4_service *svc, bool netns_cookie,
			  const union lb4_affinity_client_id *id)
{
	struct lb4_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
		.client_id	= *id,
	};
	struct lb_affinity_val *val;

	val = map_lookup_elem(&LB4_AFFINITY_MAP, &key);
	if (val != NULL) {
		__u32 now = bpf_mono_now();
		struct lb_affinity_match match = {
			.rev_nat_id	= svc->rev_nat_index,
			.backend_id	= val->backend_id,
		};

		/* We have seconds granularity for timing values here.
		 * To ensure that session affinity timeout works properly we don't include
		 * the upper bound from the time range.
		 * Session is sticky for range [current, last_used + affinity_timeout)
		 */
		if (READ_ONCE(val->last_used) +
		    bpf_sec_to_mono(svc->affinity_timeout) <= now) {
			map_delete_elem(&LB4_AFFINITY_MAP, &key);
			return 0;
		}

		if (!map_lookup_elem(&LB_AFFINITY_MATCH_MAP, &match)) {
			map_delete_elem(&LB4_AFFINITY_MAP, &key);
			return 0;
		}

		WRITE_ONCE(val->last_used, now);
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
		      const union lb4_affinity_client_id *id,
		      __u32 backend_id)
{
	__u32 now = bpf_mono_now();
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
#endif /* ENABLE_SESSION_AFFINITY */

static __always_inline __u32
lb4_affinity_backend_id_by_netns(const struct lb4_service *svc __maybe_unused,
				 union lb4_affinity_client_id *id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY)
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
#if defined(ENABLE_SESSION_AFFINITY)
	__lb4_update_affinity(svc, true, id, backend_id);
#endif
}

static __always_inline int
lb4_to_lb6(struct __ctx_buff *ctx __maybe_unused,
	   const struct iphdr *ip4 __maybe_unused,
	   int l3_off __maybe_unused)
{
#ifdef ENABLE_NAT_46X64
	union v6addr src6, dst6;

	build_v4_in_v6(&src6, ip4->saddr);
	build_v4_in_v6(&dst6, ip4->daddr);

	return ipv4_to_ipv6(ctx, l3_off, &src6, &dst6);
#else
	return DROP_NAT_46X64_DISABLED;
#endif
}

static __always_inline int lb4_local(const void *map, struct __ctx_buff *ctx,
				     int l3_off, int l4_off,
				     struct csum_offset *csum_off,
				     struct lb4_key *key,
				     struct ipv4_ct_tuple *tuple,
				     const struct lb4_service *svc,
				     struct ct_state *state, __be32 saddr,
				     bool has_l4_header,
				     const bool skip_l3_xlate)
{
	__u32 monitor; /* Deliberately ignored; regular CT will determine monitoring. */
	__be32 new_saddr = 0, new_daddr;
	__u8 flags = tuple->flags;
	struct lb4_backend *backend;
	__u32 backend_id = 0;
	int ret;
#ifdef ENABLE_SESSION_AFFINITY
	union lb4_affinity_client_id client_id = {
		.client_ip = saddr,
	};
#endif
	ret = ct_lookup4(map, tuple, ctx, l4_off, CT_SERVICE, state, &monitor);
	switch (ret) {
	case CT_NEW:
#ifdef ENABLE_SESSION_AFFINITY
		if (lb4_svc_is_affinity(svc)) {
			backend_id = lb4_affinity_backend_id_by_addr(svc, &client_id);
			if (backend_id != 0) {
				backend = lb4_lookup_backend(ctx, backend_id);
				if (backend == NULL)
					backend_id = 0;
			}
		}
#endif
		if (backend_id == 0) {
			/* No CT entry has been found, so select a svc endpoint */
			backend_id = lb4_select_backend_id(ctx, key, tuple, svc);
			backend = lb4_lookup_backend(ctx, backend_id);
			if (backend == NULL)
				goto drop_no_service;
		}

		state->backend_id = backend_id;
		state->rev_nat_index = svc->rev_nat_index;

		ret = ct_create4(map, NULL, tuple, ctx, CT_SERVICE, state, false, false);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret))
			goto drop_no_service;
		goto update_state;
	case CT_REOPENED:
	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		/* For backward-compatibility we need to update reverse NAT
		 * index in the CT_SERVICE entry for old connections, as later
		 * in the code we check whether the right backend is used.
		 * Having it set to 0 would trigger a new backend selection
		 * which would in many cases would pick a different backend.
		 */
		if (unlikely(state->rev_nat_index == 0)) {
			state->rev_nat_index = svc->rev_nat_index;
			ct_update4_rev_nat_index(map, tuple, state);
		}
		break;
	default:
		goto drop_no_service;
	}

	/* If the CT_SERVICE entry is from a non-related connection (e.g.
	 * endpoint has been removed, but its CT entries were not (it is
	 * totally possible due to the bug in DumpReliablyWithCallback)),
	 * then a wrong (=from unrelated service) backend can be selected.
	 * To avoid this, check that reverse NAT indices match. If not,
	 * select a new backend.
	 */
	if (state->rev_nat_index != svc->rev_nat_index) {
#ifdef ENABLE_SESSION_AFFINITY
		if (lb4_svc_is_affinity(svc))
			backend_id = lb4_affinity_backend_id_by_addr(svc,
								     &client_id);
#endif
		if (!backend_id) {
			backend_id = lb4_select_backend_id(ctx, key, tuple, svc);
			if (!backend_id)
				goto drop_no_service;
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
	backend = lb4_lookup_backend(ctx, state->backend_id);
	if (!backend) {
		key->backend_slot = 0;
		svc = lb4_lookup_service(key, false);
		if (!svc)
			goto drop_no_service;
		backend_id = lb4_select_backend_id(ctx, key, tuple, svc);
		backend = lb4_lookup_backend(ctx, backend_id);
		if (!backend)
			goto drop_no_service;
		state->backend_id = backend_id;
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
	if (lb4_svc_is_affinity(svc))
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

	if (!state->loopback)
#endif
		tuple->daddr = backend->address;

	return lb_skip_l4_dnat() ? CTX_ACT_OK :
	       lb4_xlate(ctx, &new_daddr, &new_saddr, &saddr,
			 tuple->nexthdr, l3_off, l4_off, csum_off, key,
			 backend, has_l4_header, skip_l3_xlate);
drop_no_service:
	tuple->flags = flags;
	return DROP_NO_SERVICE;
}

/* lb4_ctx_store_state() stores per packet load balancing state to be picked
 * up on the continuation tail call.
 * Note that the IP headers are already xlated and the tuple is re-initialized
 * from the xlated headers before restoring state.
 * NOTE: if lb_skip_l4_dnat() this is not the case as xlate is skipped. We
 * lose the updated tuple daddr in that case.
 */
static __always_inline void lb4_ctx_store_state(struct __ctx_buff *ctx,
						const struct ct_state *state,
					       __u16 proxy_port)
{
	ctx_store_meta(ctx, CB_PROXY_MAGIC, (__u32)proxy_port << 16);
	ctx_store_meta(ctx, CB_BACKEND_ID, state->backend_id);
	ctx_store_meta(ctx, CB_CT_STATE, (__u32)state->rev_nat_index << 16 |
		       state->loopback);
}

/* lb4_ctx_restore_state() restores per packet load balancing state from the
 * previous tail call.
 * tuple->flags does not need to be restored, as it will be reinitialized from
 * the packet.
 */
static __always_inline void
lb4_ctx_restore_state(struct __ctx_buff *ctx, struct ct_state *state,
		      __u32 daddr __maybe_unused, __u16 *proxy_port)
{
	__u32 meta = ctx_load_meta(ctx, CB_CT_STATE);
#ifndef DISABLE_LOOPBACK_LB
	if (meta & 1) {
		state->loopback = 1;
		state->addr = IPV4_LOOPBACK;
		state->svc_addr = daddr; /* backend address after xlate */
	}
#endif
	state->rev_nat_index = meta >> 16;

	/* Clear to not leak state to later stages of the datapath. */
	ctx_store_meta(ctx, CB_CT_STATE, 0);

	state->backend_id = ctx_load_meta(ctx, CB_BACKEND_ID);
	/* must clear to avoid policy bypass as CB_BACKEND_ID aliases CB_POLICY. */
	ctx_store_meta(ctx, CB_BACKEND_ID, 0);

	*proxy_port = ctx_load_meta(ctx, CB_PROXY_MAGIC) >> 16;
	ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);
}
#endif /* ENABLE_IPV4 */
#endif /* __LB_H_ */
