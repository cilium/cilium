/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LB_H_
#define __LB_H_

#include "bpf/compiler.h"
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
} LB6_BACKEND_MAP __section_maps_btf;

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
		__uint(key_size, sizeof(__u32));
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
} LB4_BACKEND_MAP __section_maps_btf;

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
		__uint(key_size, sizeof(__u32));
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
bool lb4_svc_is_loopback(const struct lb4_service *svc __maybe_unused)
{
	return svc->flags2 & SVC_FLAG_LOOPBACK;
}

static __always_inline
bool lb6_svc_is_loopback(const struct lb6_service *svc __maybe_unused)
{
	return svc->flags2 & SVC_FLAG_LOOPBACK;
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
bool lb4_svc_is_two_scopes(const struct lb4_service *svc)
{
	return svc->flags2 & SVC_FLAG_TWO_SCOPES;
}

static __always_inline
bool lb6_svc_is_two_scopes(const struct lb6_service *svc)
{
	return svc->flags2 & SVC_FLAG_TWO_SCOPES;
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

static __always_inline int reverse_map_l4_port(struct __ctx_buff *ctx, __u8 nexthdr,
					       __be16 port, int l4_off,
					       struct csum_offset *csum_off)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (port) {
			__be16 old_port;
			int ret;

			/* Port offsets for UDP and TCP are the same */
			ret = l4_load_port(ctx, l4_off + TCP_SPORT_OFF, &old_port);
			if (IS_ERR(ret))
				return ret;

			if (port != old_port) {
#ifdef ENABLE_SCTP
				/* This will change the SCTP checksum, which we cannot fix right now.
				 * This will likely need kernel changes before we can remove this.
				 */
				if (nexthdr == IPPROTO_SCTP)
					return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
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

static __always_inline int
lb_l4_xlate(struct __ctx_buff *ctx, __u8 nexthdr __maybe_unused, int l4_off,
	    struct csum_offset *csum_off, __be16 dport, __be16 backend_port)
{
	if (likely(backend_port) && dport != backend_port) {
		int ret;

#ifdef ENABLE_SCTP
		/* This will change the SCTP checksum, which we cannot fix right now.
		 * This will likely need kernel changes before we can remove this.
		 */
		if (nexthdr == IPPROTO_SCTP)
			return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */

		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(ctx, l4_off, TCP_DPORT_OFF, csum_off,
				     backend_port, dport);
		if (IS_ERR(ret))
			return ret;
	}

	return CTX_ACT_OK;
}

#ifdef ENABLE_IPV6
static __always_inline int __lb6_rev_nat(struct __ctx_buff *ctx, int l4_off,
					 struct ipv6_ct_tuple *tuple, int flags,
					 struct lb6_reverse_nat *nat)
{
	struct csum_offset csum_off = {};
	union v6addr old_saddr;
	union v6addr tmp;
	__u8 *new_saddr;
	__be32 sum;
	int ret;

	cilium_dbg_lb(ctx, DBG_LB6_REVERSE_NAT, nat->address.p4, nat->port);

	csum_l4_offset_and_flags(tuple->nexthdr, &csum_off);

	if (nat->port) {
		ret = reverse_map_l4_port(ctx, tuple->nexthdr, nat->port, l4_off, &csum_off);
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
	if (csum_off.offset &&
	    csum_l4_replace(ctx, l4_off, &csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}

/** Perform IPv6 reverse NAT based on reverse NAT index
 * @arg ctx		packet
 * @arg l4_off		offset to L4
 * @arg index		reverse NAT index
 * @arg tuple		tuple
 * @arg saddr_tuple	If set, tuple address will be updated with new source address
 */
static __always_inline int lb6_rev_nat(struct __ctx_buff *ctx, int l4_off,
				       __u16 index, struct ipv6_ct_tuple *tuple, int flags)
{
	struct lb6_reverse_nat *nat;

	cilium_dbg_lb(ctx, DBG_LB6_REVERSE_NAT_LOOKUP, index, 0);
	nat = map_lookup_elem(&LB6_REVERSE_NAT_MAP, &index);
	if (nat == NULL)
		return 0;

	return __lb6_rev_nat(ctx, l4_off, tuple, flags, nat);
}

static __always_inline void
lb6_fill_key(struct lb6_key *key, struct ipv6_ct_tuple *tuple)
{
	/* FIXME: set after adding support for different L4 protocols in LB */
	key->proto = 0;
	ipv6_addr_copy(&key->address, &tuple->daddr);
	key->dport = tuple->sport;
}

/** Extract IPv6 CT tuple from packet
 * @arg ctx		Packet
 * @arg ip6		Pointer to L3 header
 * @arg l3_off		Offset to L3 header
 * @arg l4_off		Offset to L4 header
 * @arg tuple		CT tuple
 *
 * Expects the ctx to be validated for direct packet access up to L4.
 *
 * Returns:
 *   - CTX_ACT_OK on successful extraction
 *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)
 *   - Negative error code
 */
static __always_inline int
lb6_extract_tuple(struct __ctx_buff *ctx, struct ipv6hdr *ip6, int l3_off,
		  int *l4_off, struct ipv6_ct_tuple *tuple)
{
	int ret;

	tuple->nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple->daddr, (union v6addr *)&ip6->daddr);
	ipv6_addr_copy(&tuple->saddr, (union v6addr *)&ip6->saddr);

	ret = ipv6_hdrlen_offset(ctx, &tuple->nexthdr, l3_off);
	if (ret < 0)
		return ret;

	*l4_off = l3_off + ret;

	switch (tuple->nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (l4_load_ports(ctx, *l4_off, &tuple->dport) < 0)
			return DROP_CT_INVALID_HDR;
		return 0;
	case IPPROTO_ICMPV6:
		return DROP_NO_SERVICE;
	default:
		return DROP_UNKNOWN_L4;
	}
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
	   const bool scope_switch, const bool check_svc_backends)
{
	struct lb6_service *svc;

	key->scope = LB_LOOKUP_SCOPE_EXT;
	key->backend_slot = 0;
	svc = map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
	if (svc) {
		if (!scope_switch || !lb6_svc_is_two_scopes(svc))
			/* Packets for L7 LB are redirected even when there are no backends. */
			return (svc->count || !check_svc_backends ||
				lb6_svc_is_l7loadbalancer(svc)) ? svc : NULL;
		key->scope = LB_LOOKUP_SCOPE_INT;
		svc = map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
		if (svc && (svc->count || !check_svc_backends || lb6_svc_is_l7loadbalancer(svc)))
			return svc;
	}

	return NULL;
}

static __always_inline struct lb6_backend *__lb6_lookup_backend(__u32 backend_id)
{
	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
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
#elif LB_SELECTION == LB_SELECTION_FIRST
/* Backend selection for tests that always chooses first slot. */
static __always_inline __u32
lb6_select_backend_id(struct __ctx_buff *ctx __maybe_unused,
		      struct lb6_key *key __maybe_unused,
		      const struct ipv6_ct_tuple *tuple,
		      const struct lb6_service *svc)
{
	struct lb6_service *be = lb6_lookup_backend_slot(ctx, key, 1);

	return be ? be->backend_id : 0;
}
#else
# error "Invalid load balancer backend selection algorithm!"
#endif /* LB_SELECTION */

static __always_inline int lb6_xlate(struct __ctx_buff *ctx, __u8 nexthdr,
				     int l3_off, int l4_off,
				     const struct lb6_key *key,
				     const struct lb6_backend *backend,
				     const bool skip_l3_xlate)
{
	const union v6addr *new_dst = &backend->address;
	struct csum_offset csum_off = {};

	csum_l4_offset_and_flags(nexthdr, &csum_off);

	if (skip_l3_xlate)
		goto l4_xlate;

	if (ipv6_store_daddr(ctx, new_dst->addr, l3_off) < 0)
		return DROP_WRITE_ERROR;
	if (csum_off.offset) {
		__be32 sum = csum_diff(key->address.addr, 16, new_dst->addr,
				       16, 0);

		if (csum_l4_replace(ctx, l4_off, &csum_off, 0, sum,
				    BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

l4_xlate:
	return lb_l4_xlate(ctx, nexthdr, l4_off, &csum_off, key->dport,
			   backend->port);
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
				     struct lb6_key *key,
				     struct ipv6_ct_tuple *tuple,
				     const struct lb6_service *svc,
				     struct ct_state *state,
				     const bool skip_l3_xlate,
				     __s8 *ext_err)
{
	__u32 monitor; /* Deliberately ignored; regular CT will determine monitoring. */
	__u8 flags = tuple->flags;
	struct lb6_backend *backend;
	__u32 backend_id = 0;
	int ret;
#ifdef ENABLE_SESSION_AFFINITY
	union lb6_affinity_client_id client_id;

	ipv6_addr_copy(&client_id.client_ip, &tuple->saddr);
#endif
	if (unlikely(svc->count == 0))
		return DROP_NO_SERVICE;

	/* See lb4_local comments re svc endpoint lookup process */
	ret = ct_lazy_lookup6(map, tuple, ctx, l4_off, ACTION_CREATE, CT_SERVICE, state, &monitor);
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

		ret = ct_create6(map, NULL, tuple, ctx, CT_SERVICE, state, false, false, ext_err);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret))
			goto drop_err;

		break;
	case CT_REPLY:
		/* See lb4_local comment */
		if (state->rev_nat_index == 0) {
			state->rev_nat_index = svc->rev_nat_index;
			ct_update_rev_nat_index(map, tuple, state);
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

			state->rev_nat_index = svc->rev_nat_index;
			ct_update_svc_entry(map, tuple, backend_id, svc->rev_nat_index);
		} else {
			backend_id = state->backend_id;
		}

		/* If the lookup fails it means the user deleted the backend out from
		 * underneath us. To resolve this fall back to hash. If this is a TCP
		 * session we are likely to get a TCP RST.
		 */
		backend = lb6_lookup_backend(ctx, backend_id);
		if (unlikely(!backend || backend->flags != BE_STATE_ACTIVE)) {
			/* Drain existing connections, but redirect new ones to only
			 * active backends.
			 */
			if (backend && !state->syn)
				break;
			key->backend_slot = 0;
			svc = lb6_lookup_service(key, false, true);
			if (!svc)
				goto drop_no_service;
			backend_id = lb6_select_backend_id(ctx, key, tuple, svc);
			backend = lb6_lookup_backend(ctx, backend_id);
			if (!backend)
				goto drop_no_service;

			state->rev_nat_index = svc->rev_nat_index;
			ct_update_svc_entry(map, tuple, backend_id, svc->rev_nat_index);
		}

		break;
	default:
		ret = DROP_UNKNOWN_CT;
		goto drop_err;
	}

	/* Restore flags so that SERVICE flag is only used in used when the
	 * service lookup happens and future lookups use EGRESS or INGRESS.
	 */
	tuple->flags = flags;
#ifdef ENABLE_SESSION_AFFINITY
	if (lb6_svc_is_affinity(svc))
		lb6_update_affinity_by_addr(svc, &client_id, backend_id);
#endif

	ipv6_addr_copy(&tuple->daddr, &backend->address);

	if (lb_skip_l4_dnat())
		return CTX_ACT_OK;

	if (likely(backend->port))
		tuple->sport = backend->port;

	return lb6_xlate(ctx, tuple->nexthdr, l3_off, l4_off,
			 key, backend, skip_l3_xlate);
drop_no_service:
	ret = DROP_NO_SERVICE;
drop_err:
	tuple->flags = flags;
	return ret;
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

	*proxy_port = ctx_load_meta(ctx, CB_PROXY_MAGIC) >> 16;
	ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);
}

#else

/* Stubs for v4-in-v6 socket cgroup hook case when only v4 is enabled to avoid
 * additional map management.
 */
static __always_inline
struct lb6_service *lb6_lookup_service(struct lb6_key *key __maybe_unused,
	   const bool scope_switch __maybe_unused, const bool check_svc_backends __maybe_unused)
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
					 struct ipv4_ct_tuple *tuple, int flags,
					 const struct lb4_reverse_nat *nat,
					 const struct ct_state *ct_state __maybe_unused,
					 bool has_l4_header)
{
	struct csum_offset csum_off = {};
	__be32 old_sip, new_sip, sum = 0;
	int ret;

	cilium_dbg_lb(ctx, DBG_LB4_REVERSE_NAT, nat->address, nat->port);

	if (has_l4_header)
		csum_l4_offset_and_flags(tuple->nexthdr, &csum_off);

	if (nat->port && has_l4_header) {
		ret = reverse_map_l4_port(ctx, tuple->nexthdr, nat->port, l4_off, &csum_off);
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

#ifndef DISABLE_LOOPBACK_LB
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
#endif

	ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, saddr),
			      &new_sip, 4, 0);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(&old_sip, 4, &new_sip, 4, sum);
	if (ipv4_csum_update_by_diff(ctx, l3_off, sum) < 0)
		return DROP_CSUM_L3;

	if (csum_off.offset &&
	    csum_l4_replace(ctx, l4_off, &csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}


/** Perform IPv4 reverse NAT based on reverse NAT index
 * @arg ctx		packet
 * @arg l3_off		offset to L3
 * @arg l4_off		offset to L4
 * @arg index		reverse NAT index
 * @arg tuple		tuple
 */
static __always_inline int lb4_rev_nat(struct __ctx_buff *ctx, int l3_off, int l4_off,
				       struct ct_state *ct_state,
				       struct ipv4_ct_tuple *tuple, int flags, bool has_l4_header)
{
	struct lb4_reverse_nat *nat;

	cilium_dbg_lb(ctx, DBG_LB4_REVERSE_NAT_LOOKUP, ct_state->rev_nat_index, 0);
	nat = map_lookup_elem(&LB4_REVERSE_NAT_MAP, &ct_state->rev_nat_index);
	if (nat == NULL)
		return 0;

	return __lb4_rev_nat(ctx, l3_off, l4_off, tuple, flags, nat,
			     ct_state, has_l4_header);
}

static __always_inline void
lb4_fill_key(struct lb4_key *key, const struct ipv4_ct_tuple *tuple)
{
	/* FIXME: set after adding support for different L4 protocols in LB */
	key->proto = 0;
	key->address = tuple->daddr;
	/* CT tuple has ports in reverse order: */
	key->dport = tuple->sport;
}

/** Extract IPv4 CT tuple from packet
 * @arg ctx		Packet
 * @arg ip4		Pointer to L3 header
 * @arg l3_off		Offset to L3 header
 * @arg l4_off		Offset to L4 header
 * @arg tuple		CT tuple
 *
 * Returns:
 *   - CTX_ACT_OK on successful extraction
 *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)
 *   - Negative error code
 */
static __always_inline int
lb4_extract_tuple(struct __ctx_buff *ctx, struct iphdr *ip4, int l3_off, int *l4_off,
		  struct ipv4_ct_tuple *tuple)
{
	int ret;

	tuple->nexthdr = ip4->protocol;
	tuple->daddr = ip4->daddr;
	tuple->saddr = ip4->saddr;

	*l4_off = l3_off + ipv4_hdrlen(ip4);

	switch (tuple->nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
#ifdef ENABLE_IPV4_FRAGMENTS
		ret = ipv4_handle_fragmentation(ctx, ip4, *l4_off,
						CT_EGRESS,
						(struct ipv4_frag_l4ports *)&tuple->dport,
						NULL);
#else
		ret = l4_load_ports(ctx, *l4_off, &tuple->dport);
#endif

		if (IS_ERR(ret))
			return ret;
		return 0;
	case IPPROTO_ICMP:
		return DROP_NO_SERVICE;
	default:
		return DROP_UNKNOWN_L4;
	}
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
				  const bool scope_switch, const bool check_svc_backends)
{
	struct lb4_service *svc;

	key->scope = LB_LOOKUP_SCOPE_EXT;
	key->backend_slot = 0;
	svc = map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
	if (svc) {
		if (!scope_switch || !lb4_svc_is_two_scopes(svc))
			/* Packets for L7 LB are redirected even when there are no backends. */
			return (svc->count || !check_svc_backends || lb4_to_lb6_service(svc) ||
				lb4_svc_is_l7loadbalancer(svc)) ? svc : NULL;
		key->scope = LB_LOOKUP_SCOPE_INT;
		svc = map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
		if (svc && (svc->count || !check_svc_backends || lb4_svc_is_l7loadbalancer(svc)))
			return svc;
	}

	return NULL;
}

static __always_inline struct lb4_backend *__lb4_lookup_backend(__u32 backend_id)
{
	return map_lookup_elem(&LB4_BACKEND_MAP, &backend_id);
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
#elif LB_SELECTION == LB_SELECTION_FIRST
/* Backend selection for tests that always chooses first slot. */
static __always_inline __u32
lb4_select_backend_id(struct __ctx_buff *ctx,
		      struct lb4_key *key,
		      const struct ipv4_ct_tuple *tuple __maybe_unused,
		      const struct lb4_service *svc)
{
	struct lb4_service *be = lb4_lookup_backend_slot(ctx, key, 1);

	return be ? be->backend_id : 0;
}
#else
# error "Invalid load balancer backend selection algorithm!"
#endif /* LB_SELECTION */

static __always_inline int
lb4_xlate(struct __ctx_buff *ctx, __be32 *new_saddr __maybe_unused,
	  __be32 *old_saddr __maybe_unused, __u8 nexthdr __maybe_unused, int l3_off,
	  int l4_off, struct lb4_key *key,
	  const struct lb4_backend *backend __maybe_unused, bool has_l4_header,
	  const bool skip_l3_xlate)
{
	const __be32 *new_daddr = &backend->address;
	struct csum_offset csum_off = {};
	__be32 sum;
	int ret;

	if (has_l4_header)
		csum_l4_offset_and_flags(nexthdr, &csum_off);

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
	if (ipv4_csum_update_by_diff(ctx, l3_off, sum) < 0)
		return DROP_CSUM_L3;
	if (csum_off.offset) {
		if (csum_l4_replace(ctx, l4_off, &csum_off, 0, sum,
				    BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

l4_xlate:
	return has_l4_header ? lb_l4_xlate(ctx, nexthdr, l4_off, &csum_off,
					   key->dport, backend->port) :
			       CTX_ACT_OK;
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
				     struct lb4_key *key,
				     struct ipv4_ct_tuple *tuple,
				     const struct lb4_service *svc,
				     struct ct_state *state,
				     bool has_l4_header,
				     const bool skip_l3_xlate,
				     __u32 *cluster_id __maybe_unused,
				     __s8 *ext_err)
{
	__u32 monitor; /* Deliberately ignored; regular CT will determine monitoring. */
	__be32 saddr = tuple->saddr;
	__u8 flags = tuple->flags;
	struct lb4_backend *backend;
	__u32 backend_id = 0;
	__be32 new_saddr = 0;
	int ret;
#ifdef ENABLE_SESSION_AFFINITY
	union lb4_affinity_client_id client_id = {
		.client_ip = saddr,
	};
#endif
	if (unlikely(svc->count == 0))
		return DROP_NO_SERVICE;

	ret = ct_lazy_lookup4(map, tuple, ctx, l4_off, has_l4_header, ACTION_CREATE,
			      CT_SERVICE, state, &monitor);
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

		ret = ct_create4(map, NULL, tuple, ctx, CT_SERVICE, state, false, false, ext_err);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret))
			goto drop_err;

		break;
	case CT_REPLY:
		/* For backward-compatibility we need to update reverse NAT
		 * index in the CT_SERVICE entry for old connections, as later
		 * in the code we check whether the right backend is used.
		 * Having it set to 0 would trigger a new backend selection
		 * which would in many cases would pick a different backend.
		 */
		if (unlikely(state->rev_nat_index == 0)) {
			state->rev_nat_index = svc->rev_nat_index;
			ct_update_rev_nat_index(map, tuple, state);
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

			state->rev_nat_index = svc->rev_nat_index;
			ct_update_svc_entry(map, tuple, backend_id, svc->rev_nat_index);
		} else {
			backend_id = state->backend_id;
		}

		/* If the lookup fails it means the user deleted the backend out from
		 * underneath us. To resolve this fall back to hash. If this is a TCP
		 * session we are likely to get a TCP RST.
		 */
		backend = lb4_lookup_backend(ctx, backend_id);
		if (unlikely(!backend || backend->flags != BE_STATE_ACTIVE)) {
			/* Drain existing connections, but redirect new ones to only
			 * active backends.
			 */
			if (backend && !state->syn)
				break;
			key->backend_slot = 0;
			svc = lb4_lookup_service(key, false, true);
			if (!svc)
				goto drop_no_service;
			backend_id = lb4_select_backend_id(ctx, key, tuple, svc);
			backend = lb4_lookup_backend(ctx, backend_id);
			if (!backend)
				goto drop_no_service;

			state->rev_nat_index = svc->rev_nat_index;
			ct_update_svc_entry(map, tuple, backend_id, svc->rev_nat_index);
		}

		break;
	default:
		ret = DROP_UNKNOWN_CT;
		goto drop_err;
	}

#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
	*cluster_id = backend->cluster_id;
#endif

	/* Restore flags so that SERVICE flag is only used in used when the
	 * service lookup happens and future lookups use EGRESS or INGRESS.
	 */
	tuple->flags = flags;
#ifdef ENABLE_SESSION_AFFINITY
	if (lb4_svc_is_affinity(svc))
		lb4_update_affinity_by_addr(svc, &client_id, backend_id);
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
		state->svc_addr = saddr;
	}

	if (!state->loopback)
#endif
		tuple->daddr = backend->address;

	if (lb_skip_l4_dnat())
		return CTX_ACT_OK;

	/* CT tuple contains ports in reverse order: */
	if (likely(backend->port))
		tuple->sport = backend->port;

	return lb4_xlate(ctx, &new_saddr, &saddr,
			 tuple->nexthdr, l3_off, l4_off, key,
			 backend, has_l4_header, skip_l3_xlate);
drop_no_service:
	ret = DROP_NO_SERVICE;
drop_err:
	tuple->flags = flags;
	return ret;
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
					       __u16 proxy_port, __u32 cluster_id)
{
	ctx_store_meta(ctx, CB_PROXY_MAGIC, (__u32)proxy_port << 16);
	ctx_store_meta(ctx, CB_CT_STATE, (__u32)state->rev_nat_index << 16 |
#ifndef DISABLE_LOOPBACK_LB
		       state->loopback);
#else
		       0);
#endif
	ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, cluster_id);
}

/* lb4_ctx_restore_state() restores per packet load balancing state from the
 * previous tail call.
 * tuple->flags does not need to be restored, as it will be reinitialized from
 * the packet.
 */
static __always_inline void
lb4_ctx_restore_state(struct __ctx_buff *ctx, struct ct_state *state,
		       __u32 daddr __maybe_unused, __u16 *proxy_port,
		       __u32 *cluster_id __maybe_unused)
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

	*proxy_port = ctx_load_meta(ctx, CB_PROXY_MAGIC) >> 16;
	ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);

#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
	*cluster_id = ctx_load_meta(ctx, CB_CLUSTER_ID_EGRESS);
	ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, 0);
#endif
}

#endif /* ENABLE_IPV4 */

/* sock_local_cookie retrieves the socket cookie for the
 * passed socket structure.
 */
static __always_inline __maybe_unused
__sock_cookie sock_local_cookie(struct bpf_sock_addr *ctx)
{
#ifdef HAVE_SOCKET_COOKIE
	/* prandom() breaks down on UDP, hence preference is on
	 * socket cookie as built-in selector. On older kernels,
	 * get_socket_cookie() provides a unique per netns cookie
	 * for the life-time of the socket. For newer kernels this
	 * is fixed to be a unique system _global_ cookie. Older
	 * kernels could have a cookie collision when two pods with
	 * different netns talk to same service backend, but that
	 * is fine since we always reverse translate to the same
	 * service IP/port pair. The only case that could happen
	 * for older kernels is that we have a cookie collision
	 * where one pod talks to the service IP/port and the
	 * other pod talks to that same specific backend IP/port
	 * directly _w/o_ going over service IP/port. Then the
	 * reverse sock addr is translated to the service IP/port.
	 * With a global socket cookie this collision cannot take
	 * place. There, only the even more unlikely case could
	 * happen where the same UDP socket talks first to the
	 * service and then to the same selected backend IP/port
	 * directly which can be considered negligible.
	 */
       return get_socket_cookie(ctx);
#else
       return ctx->protocol == IPPROTO_TCP ? get_prandom_u32() : 0;
#endif
}
#endif /* __LB_H_ */
