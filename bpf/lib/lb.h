/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "bpf/compiler.h"
#include "csum.h"
#include "conntrack.h"
#include "ipv4.h"
#include "hash.h"
#include "ids.h"
#include "nat_46x64.h"
#include "ratelimit.h"

#ifndef SKIP_CALLS_MAP
#include "drop.h"
#endif

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct skip_lb6_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_SKIP_MAP_MAX_ENTRIES);
} LB6_SKIP_MAP __section_maps_btf;
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct skip_lb4_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_SKIP_MAP_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} LB4_SKIP_MAP __section_maps_btf;

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

#ifndef DSR_XLATE_MODE
# define DSR_XLATE_MODE		0
# define DSR_XLATE_FRONTEND	1
#endif
#ifdef LB_DEBUG
#define cilium_dbg_lb cilium_dbg
#else
#define cilium_dbg_lb(a, b, c, d)
#endif

#ifdef ENABLE_ACTIVE_CONNECTION_TRACKING
#include "act.h"
#endif

static __always_inline bool lb_is_svc_proto(__u8 proto)
{
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif /* ENABLE_SCTP */
		return true;
	default:
		return false;
	}
}

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

#ifdef ENABLE_LOCAL_REDIRECT_POLICY
static __always_inline
bool lb4_svc_is_localredirect(const struct lb4_service *svc)
{
	return svc->flags2 & SVC_FLAG_LOCALREDIRECT;
}

static __always_inline
bool lb6_svc_is_localredirect(const struct lb6_service *svc)
{
	return svc->flags2 & SVC_FLAG_LOCALREDIRECT;
}
#endif /* ENABLE_LOCAL_REDIRECT_POLICY */

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
					       __be16 old_port, __be16 port, int l4_off,
					       struct csum_offset *csum_off)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (port) {
			int ret;

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
					 struct ipv6_ct_tuple *tuple,
					 struct lb6_reverse_nat *nat)
{
	struct csum_offset csum_off = {};
	union v6addr old_saddr __align_stack_8;
	__be32 sum;
	int ret;

	cilium_dbg_lb(ctx, DBG_LB6_REVERSE_NAT, nat->address.p4, nat->port);

	csum_l4_offset_and_flags(tuple->nexthdr, &csum_off);

	if (nat->port) {
		ret = reverse_map_l4_port(ctx, tuple->nexthdr, tuple->dport,
					  nat->port, l4_off, &csum_off);
		if (IS_ERR(ret))
			return ret;
	}

	ipv6_addr_copy(&old_saddr, &tuple->saddr);
	ipv6_addr_copy(&tuple->saddr, &nat->address);

	ret = ipv6_store_saddr(ctx, nat->address.addr, ETH_HLEN);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(old_saddr.addr, 16, nat->address.addr, 16, 0);
	if (csum_off.offset &&
	    csum_l4_replace(ctx, l4_off, &csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}

static __always_inline struct lb6_reverse_nat *
lb6_lookup_rev_nat_entry(struct __ctx_buff *ctx __maybe_unused, __u16 index)
{
	cilium_dbg_lb(ctx, DBG_LB6_REVERSE_NAT_LOOKUP, index, 0);

	return map_lookup_elem(&LB6_REVERSE_NAT_MAP, &index);
}

/** Perform IPv6 reverse NAT based on reverse NAT index
 * @arg ctx		packet
 * @arg l4_off		offset to L4
 * @arg index		reverse NAT index
 * @arg tuple		tuple
 */
static __always_inline int lb6_rev_nat(struct __ctx_buff *ctx, int l4_off,
				       __u16 index, struct ipv6_ct_tuple *tuple)
{
	struct lb6_reverse_nat *nat;

	nat = lb6_lookup_rev_nat_entry(ctx, index);
	if (nat == NULL)
		return 0;

	return __lb6_rev_nat(ctx, l4_off, tuple, nat);
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
	if (ret < 0) {
		/* Make sure *l4_off is always initialized on return, because
		 * Clang can spill it from a register to the stack even in error
		 * flows where this value is no longer used, and this pattern is
		 * rejected by the verifier.
		 * Use a prominent value (-1) to highlight any potential misuse.
		 */
		*l4_off = -1;
		return ret;
	}

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
		return DROP_UNSUPP_SERVICE_PROTO;
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
				       const bool scope_switch)
{
	struct lb6_service *svc;

	key->scope = LB_LOOKUP_SCOPE_EXT;
	key->backend_slot = 0;
	svc = map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
	if (svc) {
		if (!scope_switch || !lb6_svc_is_two_scopes(svc))
			return svc;
		key->scope = LB_LOOKUP_SCOPE_INT;
		svc = map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
	}

	return svc;
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

	if (netns_cookie)
		key.client_id.client_cookie = id->client_cookie;
	else
		ipv6_addr_copy_unaligned(&key.client_id.client_ip, &id->client_ip);

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

	if (netns_cookie)
		key.client_id.client_cookie = id->client_cookie;
	else
		ipv6_addr_copy_unaligned(&key.client_id.client_ip, &id->client_ip);

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

#ifdef ENABLE_LOCAL_REDIRECT_POLICY
static __always_inline bool
lb6_skip_xlate_from_ctx_to_svc(__net_cookie cookie,
			       union v6addr addr __maybe_unused, __be16 port __maybe_unused)
{
	struct skip_lb6_key key;
	__u8 *val = NULL;

	memset(&key, 0, sizeof(key));
	key.netns_cookie = cookie;
	key.address = addr;
	key.port = port;
	val = map_lookup_elem(&LB6_SKIP_MAP, &key);
	if (val)
		return true;
	return false;
}
#endif /* ENABLE_LOCAL_REDIRECT_POLICY */

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

	state->rev_nat_index = svc->rev_nat_index;

	/* See lb4_local comments re svc endpoint lookup process */
	ret = ct_lazy_lookup6(map, tuple, ctx, l4_off, CT_SERVICE,
			      SCOPE_REVERSE, CT_ENTRY_SVC, state, &monitor);
	if (ret < 0)
		goto drop_err;

	switch (ret) {
	case CT_NEW:
		if (unlikely(svc->count == 0))
			goto no_service;

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
				goto no_service;
		}

		state->backend_id = backend_id;

		ret = ct_create6(map, NULL, tuple, ctx, CT_SERVICE, state, ext_err);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret))
			goto drop_err;

#ifdef ENABLE_ACTIVE_CONNECTION_TRACKING
		_lb_act_conn_open(ct_state->rev_nat_index, backend->zone);
#endif

		break;
	case CT_REPLY:
		backend_id = state->backend_id;

		/* If the lookup fails it means the user deleted the backend out from
		 * underneath us. To resolve this fall back to hash. If this is a TCP
		 * session we are likely to get a TCP RST.
		 */
		backend = lb6_lookup_backend(ctx, backend_id);
#ifdef ENABLE_ACTIVE_CONNECTION_TRACKING
		if (state->closing && backend)
			_lb_act_conn_closed(svc->rev_nat_index, backend->zone);
#endif
		if (unlikely(!backend || backend->flags != BE_STATE_ACTIVE)) {
			/* Drain existing connections, but redirect new ones to only
			 * active backends.
			 */
			if (backend && !state->syn)
				break;

			if (unlikely(svc->count == 0))
				goto no_service;

			backend_id = lb6_select_backend_id(ctx, key, tuple, svc);
			backend = lb6_lookup_backend(ctx, backend_id);
			if (!backend)
				goto no_service;

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
no_service:
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
	state->rev_nat_index = (__u16)ctx_load_and_clear_meta(ctx, CB_CT_STATE);

	/* No loopback support for IPv6, see lb6_local() above. */

	*proxy_port = ctx_load_and_clear_meta(ctx, CB_PROXY_MAGIC) >> 16;
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
					 struct ipv4_ct_tuple *tuple,
					 const struct lb4_reverse_nat *nat,
					 bool loopback __maybe_unused, bool has_l4_header)
{
	__be32 old_sip = tuple->saddr, sum = 0;
	int ret;

	cilium_dbg_lb(ctx, DBG_LB4_REVERSE_NAT, nat->address, nat->port);

	tuple->saddr = nat->address;

#ifndef DISABLE_LOOPBACK_LB
	if (loopback) {
		/* The packet was looped back to the sending endpoint on the
		 * forward service translation. This implies that the original
		 * source address of the packet is the source address of the
		 * current packet. We therefore need to make the current source
		 * address the new destination address.
		 */
		__be32 old_dip = tuple->daddr;

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
			      &nat->address, 4, 0);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(&old_sip, 4, &nat->address, 4, sum);
	if (ipv4_csum_update_by_diff(ctx, l3_off, sum) < 0)
		return DROP_CSUM_L3;

	if (has_l4_header) {
		struct csum_offset csum_off = {};

		csum_l4_offset_and_flags(tuple->nexthdr, &csum_off);

		if (nat->port) {
			/* We expect to only handle replies. Thus the extracted CT tuple
			 * will have the packet's source port in .dport.
			 */
			ret = reverse_map_l4_port(ctx, tuple->nexthdr, tuple->dport,
						  nat->port, l4_off, &csum_off);
			if (IS_ERR(ret))
				return ret;
		}

		if (csum_off.offset &&
		    csum_l4_replace(ctx, l4_off, &csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

	return 0;
}

static __always_inline struct lb4_reverse_nat *
lb4_lookup_rev_nat_entry(struct __ctx_buff *ctx __maybe_unused, __u16 index)
{
	cilium_dbg_lb(ctx, DBG_LB4_REVERSE_NAT_LOOKUP, index, 0);

	return map_lookup_elem(&LB4_REVERSE_NAT_MAP, &index);
}

/** Perform IPv4 reverse NAT based on reverse NAT index
 * @arg ctx		packet
 * @arg l3_off		offset to L3
 * @arg l4_off		offset to L4
 * @arg index		reverse NAT index
 * @arg loopback	loopback connection
 * @arg tuple		tuple
 */
static __always_inline int lb4_rev_nat(struct __ctx_buff *ctx, int l3_off, int l4_off,
				       __u16 index, bool loopback,
				       struct ipv4_ct_tuple *tuple, bool has_l4_header)
{
	struct lb4_reverse_nat *nat;

	nat = lb4_lookup_rev_nat_entry(ctx, index);
	if (nat == NULL)
		return 0;

	return __lb4_rev_nat(ctx, l3_off, l4_off, tuple, nat,
			     loopback, has_l4_header);
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
		ret = ipv4_load_l4_ports(ctx, ip4, *l4_off, CT_EGRESS,
					 &tuple->dport, NULL);

		if (IS_ERR(ret))
			return ret;
		return 0;
	case IPPROTO_ICMP:
		return DROP_UNSUPP_SERVICE_PROTO;
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
				       const bool scope_switch)
{
	struct lb4_service *svc;

	key->scope = LB_LOOKUP_SCOPE_EXT;
	key->backend_slot = 0;
	svc = map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
	if (svc) {
		if (!scope_switch || !lb4_svc_is_two_scopes(svc))
			return svc;
		key->scope = LB_LOOKUP_SCOPE_INT;
		svc = map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
	}

	return svc;
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

#ifdef ENABLE_LOCAL_REDIRECT_POLICY
/* Service translation logic for a local-redirect service can cause packets to
 * be looped back to a service node-local backend after translation. This can
 * happen when the node-local backend itself tries to connect to the service
 * frontend for which it acts as a backend. There are cases where this can break
 * traffic flow if the backend needs to forward the redirected traffic to the
 * actual service frontend. Hence, allow service translation for pod traffic
 * getting redirected to backend (across network namespaces), but skip service
 * translation for backend to itself or another service backend within the same
 * namespace. Currently only v4 and v4-in-v6, but no plain v6 is supported.
 *
 * For example, in EKS cluster, a local-redirect service exists with the AWS
 * metadata IP, port as the frontend <169.254.169.254, 80> and kiam proxy as a
 * backend Pod. When traffic destined to the frontend originates from the kiam
 * Pod in namespace ns1 (host ns when the kiam proxy Pod is deployed in
 * hostNetwork mode or regular Pod ns) and the Pod is selected as a backend, the
 * traffic would get looped back to the proxy Pod.
 */
static __always_inline bool
lb4_skip_xlate_from_ctx_to_svc(__net_cookie cookie,
			       __be32 address __maybe_unused, __be16 port __maybe_unused)
{
	struct skip_lb4_key key;
	__u8 *val = NULL;

	memset(&key, 0, sizeof(key));
	key.netns_cookie = cookie;
	key.address = address;
	key.port = port;
	val = map_lookup_elem(&LB4_SKIP_MAP, &key);
	if (val)
		return true;
	return false;
}
#endif /* ENABLE_LOCAL_REDIRECT_POLICY */

static __always_inline int lb4_local(const void *map, struct __ctx_buff *ctx,
				     bool is_fragment, int l3_off, int l4_off,
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

	state->rev_nat_index = svc->rev_nat_index;

	ret = ct_lazy_lookup4(map, tuple, ctx, is_fragment, l4_off, has_l4_header,
			      CT_SERVICE, SCOPE_REVERSE, CT_ENTRY_SVC, state, &monitor);
	if (ret < 0)
		goto drop_err;

	switch (ret) {
	case CT_NEW:
		if (unlikely(svc->count == 0))
			goto no_service;

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
				goto no_service;
		}

		state->backend_id = backend_id;

		ret = ct_create4(map, NULL, tuple, ctx, CT_SERVICE, state, ext_err);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret))
			goto drop_err;

#ifdef ENABLE_ACTIVE_CONNECTION_TRACKING
		_lb_act_conn_open(state->rev_nat_index, backend->zone);
#endif

		break;
	case CT_REPLY:
		backend_id = state->backend_id;

		/* If the lookup fails it means the user deleted the backend out from
		 * underneath us. To resolve this fall back to hash. If this is a TCP
		 * session we are likely to get a TCP RST.
		 */
		backend = lb4_lookup_backend(ctx, backend_id);
#ifdef ENABLE_ACTIVE_CONNECTION_TRACKING
		if (state->closing && backend)
			_lb_act_conn_closed(svc->rev_nat_index, backend->zone);
#endif
		if (unlikely(!backend || backend->flags != BE_STATE_ACTIVE)) {
			/* Drain existing connections, but redirect new ones to only
			 * active backends.
			 */
			if (backend && !state->syn)
				break;

			if (unlikely(svc->count == 0))
				goto no_service;

			backend_id = lb4_select_backend_id(ctx, key, tuple, svc);
			backend = lb4_lookup_backend(ctx, backend_id);
			if (!backend)
				goto no_service;

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
no_service:
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
		       __u16 *proxy_port, __u32 *cluster_id __maybe_unused)
{
	__u32 meta = ctx_load_and_clear_meta(ctx, CB_CT_STATE);
#ifndef DISABLE_LOOPBACK_LB
	if (meta & 1)
		state->loopback = 1;
#endif
	state->rev_nat_index = meta >> 16;

	*proxy_port = ctx_load_and_clear_meta(ctx, CB_PROXY_MAGIC) >> 16;

#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
	*cluster_id = ctx_load_and_clear_meta(ctx, CB_CLUSTER_ID_EGRESS);
#endif
}

/* Because we use tail calls and this file is included in bpf_sock.h */
#ifndef SKIP_CALLS_MAP
#ifdef SERVICE_NO_BACKEND_RESPONSE

#define ICMP_PACKET_MAX_SAMPLE_SIZE 64

static __always_inline
__wsum icmp_wsum_accumulate(void *data_start, void *data_end, int sample_len);

static __always_inline
int __tail_no_service_ipv4(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *ethhdr;
	struct iphdr *ip4;
	struct icmphdr *icmphdr;
	union macaddr smac = {};
	union macaddr dmac = {};
	__be32	saddr;
	__be32	daddr;
	__u8	tos;
	__wsum csum;
	int sample_len;
	int ret;
	const int inner_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) +
		sizeof(struct icmphdr);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* copy the incoming src and dest IPs and mac addresses to the stack.
	 * the pointers will not be valid after adding headroom.
	 */

	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		return DROP_INVALID;

	if (eth_load_daddr(ctx, dmac.addr, 0) < 0)
		return DROP_INVALID;

	saddr = ip4->saddr;
	daddr = ip4->daddr;
	tos = ip4->tos;

	/* Resize to ethernet header + 64 bytes or less */
	sample_len = ctx_full_len(ctx);
	if (sample_len > ICMP_PACKET_MAX_SAMPLE_SIZE)
		sample_len = ICMP_PACKET_MAX_SAMPLE_SIZE;
	ctx_adjust_troom(ctx, sample_len + sizeof(struct ethhdr) - ctx_full_len(ctx));

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	/* Calculate the checksum of the ICMP sample */
	csum = icmp_wsum_accumulate(data + sizeof(struct ethhdr), data_end, sample_len);

	/* We need to insert a IPv4 and ICMP header before the original packet.
	 * Make that room.
	 */

#if __ctx_is == __ctx_xdp
	ret = xdp_adjust_head(ctx, 0 - (int)(sizeof(struct iphdr) + sizeof(struct icmphdr)));
#else
	ret = skb_adjust_room(ctx, sizeof(struct iphdr) + sizeof(struct icmphdr),
			      BPF_ADJ_ROOM_MAC, 0);
#endif

	if (ret < 0)
		return DROP_INVALID;

	/* changing size invalidates pointers, so we need to re-fetch them. */
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	/* Bound check all 3 headers at once. */
	if (data + inner_offset > data_end)
		return DROP_INVALID;

	/* Write reversed eth header, ready for egress */
	ethhdr = data;
	memcpy(ethhdr->h_dest, smac.addr, sizeof(smac.addr));
	memcpy(ethhdr->h_source, dmac.addr, sizeof(dmac.addr));
	ethhdr->h_proto = bpf_htons(ETH_P_IP);

	/* Write reversed ip header, ready for egress */
	ip4 = data + sizeof(struct ethhdr);
	ip4->version = 4;
	ip4->ihl = sizeof(struct iphdr) >> 2;
	ip4->tos = tos;
	ip4->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct icmphdr) +
		       (__u16)sample_len);
	ip4->id = 0;
	ip4->frag_off = 0;
	ip4->ttl = IPDEFTTL;
	ip4->protocol = IPPROTO_ICMP;
	ip4->check = 0;
	ip4->daddr = saddr;
	ip4->saddr = daddr;
	ip4->check = csum_fold(csum_diff(ip4, 0, ip4, sizeof(struct iphdr), 0));

	/* Write reversed icmp header */
	icmphdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	icmphdr->type = ICMP_DEST_UNREACH;
	icmphdr->code = ICMP_PORT_UNREACH;
	icmphdr->checksum = 0;
	icmphdr->un.gateway = 0;

	/* Add ICMP header checksum to sum of its body */
	csum += csum_diff(icmphdr, 0, icmphdr, sizeof(struct icmphdr), 0);
	icmphdr->checksum = csum_fold(csum);

	/* Redirect ICMP to the interface we received it on. */
	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY,
			   ctx_get_ifindex(ctx));
	return ctx_redirect(ctx, ctx_get_ifindex(ctx), 0);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NO_SERVICE)
int tail_no_service_ipv4(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	int ret;

	ret = __tail_no_service_ipv4(ctx);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_sec_identity, ret,
			CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}
#endif /* SERVICE_NO_BACKEND_RESPONSE */
#endif /* SKIP_CALLS_MAP */

#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6

/* Because we use tail calls and this file is included in bpf_sock.h */
#ifndef SKIP_CALLS_MAP
#ifdef SERVICE_NO_BACKEND_RESPONSE

#define ICMPV6_PACKET_MAX_SAMPLE_SIZE 1280 - sizeof(struct ipv6hdr) - sizeof(struct icmp6hdr)

static __always_inline
__wsum icmp_wsum_accumulate(void *data_start, void *data_end, int sample_len);

/* The IPv6 pseudo-header */
struct ipv6_pseudo_header_t {
	union {
		struct header {
			struct in6_addr src_ip;
			struct in6_addr dst_ip;
			__be32 top_level_length;
			__u8 zero[3];
			__u8 next_header;
		} __packed fields;
		__u16 words[20];
	};
};

static __always_inline
int __tail_no_service_ipv6(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *ethhdr;
	struct ipv6hdr *ip6;
	struct icmp6hdr *icmphdr;
	struct ipv6_pseudo_header_t pseudo_header;
	union macaddr smac = {};
	union macaddr dmac = {};
	struct in6_addr saddr;
	struct in6_addr daddr;
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_ICMPV6,
	};
	/* Rate limit to 100 ICMPv6 replies per second, burstable to 1000 responses/s */
	struct ratelimit_settings settings = {
		.bucket_size = 1000,
		.tokens_per_topup = 100,
		.topup_interval_ns = NSEC_PER_SEC,
	};
	__wsum csum;
	__u64 sample_len;
	int i;
	int ret;
	const int inner_offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		sizeof(struct icmp6hdr);

	rkey.key.icmpv6.netdev_idx = ctx_get_ifindex(ctx);
	if (!ratelimit_check_and_take(&rkey, &settings))
		return DROP_RATE_LIMITED;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* copy the incoming src and dest IPs and mac addresses to the stack.
	 * the pointers will not be valid after adding headroom.
	 */

	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		return DROP_INVALID;

	if (eth_load_daddr(ctx, dmac.addr, 0) < 0)
		return DROP_INVALID;

	memcpy(&saddr, &ip6->saddr, sizeof(struct in6_addr));
	memcpy(&daddr, &ip6->daddr, sizeof(struct in6_addr));

	/* Resize to min MTU - IPv6 hdr + ICMPv6 hdr */
	sample_len = ctx_full_len(ctx);
	if (sample_len > (__u64)ICMPV6_PACKET_MAX_SAMPLE_SIZE)
		sample_len = ICMPV6_PACKET_MAX_SAMPLE_SIZE;
	ctx_adjust_troom(ctx, sample_len + sizeof(struct ethhdr) - ctx_full_len(ctx));

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	/* Calculate the unfolded checksum of the ICMPv6 sample */
	csum = icmp_wsum_accumulate(data + sizeof(struct ethhdr), data_end, sample_len);

	/* We need to insert a IPv6 and ICMPv6 header before the original packet.
	 * Make that room.
	 */

#if __ctx_is == __ctx_xdp
	ret = xdp_adjust_head(ctx, 0 - (int)(sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr)));
#else
	ret = skb_adjust_room(ctx, sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr),
			      BPF_ADJ_ROOM_MAC, 0);
#endif

	if (ret < 0)
		return DROP_INVALID;

	/* changing size invalidates pointers, so we need to re-fetch them. */
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	/* Bound check all 3 headers at once. */
	if (data + inner_offset > data_end)
		return DROP_INVALID;

	/* Write reversed eth header, ready for egress */
	ethhdr = data;
	memcpy(ethhdr->h_dest, smac.addr, sizeof(smac.addr));
	memcpy(ethhdr->h_source, dmac.addr, sizeof(dmac.addr));
	ethhdr->h_proto = bpf_htons(ETH_P_IPV6);

	/* Write reversed ip header, ready for egress */
	ip6 = data + sizeof(struct ethhdr);
	ip6->version = 6;
	ip6->priority = 0;
	ip6->flow_lbl[0] = 0;
	ip6->flow_lbl[1] = 0;
	ip6->flow_lbl[2] = 0;
	ip6->payload_len = bpf_htons(sizeof(struct icmp6hdr) + (__u16)sample_len);
	ip6->nexthdr = IPPROTO_ICMPV6;
	ip6->hop_limit = IPDEFTTL;
	memcpy(&ip6->daddr, &saddr, sizeof(struct in6_addr));
	memcpy(&ip6->saddr, &daddr, sizeof(struct in6_addr));

	/* Write reversed icmp header */
	icmphdr = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	icmphdr->icmp6_type = ICMPV6_DEST_UNREACH;
	icmphdr->icmp6_code = ICMPV6_PORT_UNREACH;
	icmphdr->icmp6_cksum = 0;
	icmphdr->icmp6_dataun.un_data32[0] = 0;

	/* Add the ICMP header to the checksum (only type and code are non-zero) */
	csum += ((__u16)icmphdr->icmp6_code) << 8 | (__u16)icmphdr->icmp6_type;

	/* Fill pseudo header */
	memcpy(&pseudo_header.fields.src_ip, &ip6->saddr, sizeof(struct in6_addr));
	memcpy(&pseudo_header.fields.dst_ip, &ip6->daddr, sizeof(struct in6_addr));
	pseudo_header.fields.top_level_length = bpf_htonl(sizeof(struct icmp6hdr) +
						(__u32)sample_len);
	__bpf_memzero(pseudo_header.fields.zero, sizeof(pseudo_header.fields.zero));
	pseudo_header.fields.next_header = IPPROTO_ICMPV6;

	#pragma unroll
	for (i = 0; i < (int)(sizeof(pseudo_header.words) / sizeof(__u16)); i++)
		csum += pseudo_header.words[i];

	icmphdr->icmp6_cksum = csum_fold(csum);

	/* Redirect ICMP to the interface we received it on. */
	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY,
			   ctx_get_ifindex(ctx));
	return ctx_redirect(ctx, ctx_get_ifindex(ctx), 0);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NO_SERVICE)
int tail_no_service_ipv6(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	int ret;

	ret = __tail_no_service_ipv6(ctx);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_sec_identity, ret,
			CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}
#endif /* SERVICE_NO_BACKEND_RESPONSE */
#endif /* SKIP_CALLS_MAP */
#endif /* ENABLE_IPV6 */

#ifdef SERVICE_NO_BACKEND_RESPONSE

static __always_inline
__wsum icmp_wsum_accumulate(void *data_start, void *data_end, int sample_len)
{
	/* Unrolled loop to calculate the checksum of the ICMP sample
	 * Done manually because the compiler refuses with #pragma unroll
	 */
	__wsum wsum = 0;

	#define body(i) if ((i) > sample_len) \
		return wsum; \
	if (data_start + (i) + sizeof(__u16) > data_end) { \
		if (data_start + (i) + sizeof(__u8) <= data_end)\
			wsum += *(__u8 *)(data_start + (i)); \
		return wsum; \
	} \
	wsum += *(__u16 *)(data_start + (i));

	#define body4(i) body(i)\
		body(i + 2) \
		body(i + 4) \
		body(i + 6)

	#define body16(i) body4(i)\
		body4(i + 8) \
		body4(i + 16) \
		body4(i + 24)

	#define body128(i) body16(i)\
		body16(i + 32) \
		body16(i + 64) \
		body16(i + 96)

	body128(0)
	body128(256)
	body128(512)
	body128(768)
	body128(1024)

	return wsum;
}

#endif /* SERVICE_NO_BACKEND_RESPONSE */

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
