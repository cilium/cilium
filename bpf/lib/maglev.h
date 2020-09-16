/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __MAGLEV_H_
#define __MAGLEV_H_

#define INIT_JHASH_SEED    ((CILIUM_LB_MAP_MAX_ENTRIES >> 4) * MAGLEV_RING_SIZE)
#define INIT_JHASH_SEED_V6 CILIUM_LB_MAP_MAX_ENTRIES

struct bpf_elf_map __section_maps LB_MAGLEV_RING_MAP = {
    .type		= BPF_MAP_TYPE_HASH_OF_MAPS,
    .size_key	= sizeof(__u16),
    .size_value	= sizeof(__u32),
    .pinning	= PIN_GLOBAL_NS,
    .max_elem	= CILIUM_LB_MAP_MAX_ENTRIES,
    .flags      = CONDITIONAL_PREALLOC,
};

static __always_inline void *lb_select_maglev_map(__u16 svc_id)
{
	return map_lookup_elem(&LB_MAGLEV_RING_MAP, &svc_id);
}

static __always_inline int lb_select_backend(__u32 hash, __u16 svc_id)
{
	void *maglev_map;

	if ((maglev_map = lb_select_maglev_map(svc_id)) != NULL) {
		__s32 *backend_id;

		if ((backend_id = map_lookup_elem(maglev_map, &hash)) != NULL) {
			return *backend_id;
		}
		return -1;
	}
	return -2;
}

#ifdef ENABLE_IPV6

#ifdef __BPF_CTX_XDP_H_

static __always_inline __u32 get_tuple6_hash(__attribute__((unused)) struct __ctx_buff *ctx,
					     struct ipv6_ct_tuple *tuple)
{
	return jhash_2words(jhash(tuple->saddr.addr, 16, INIT_JHASH_SEED_V6),
			    ((__u32) tuple->dport << 16) | tuple->sport,
			    INIT_JHASH_SEED);
}

#else /*!__BPF_CTX_XDP_H_ */

static __always_inline __u32 get_tuple6_hash(struct __ctx_buff *ctx,
					     __attribute__((unused)) struct ipv6_ct_tuple *tuple)
{
	return get_hash_recalc(ctx);
}

#endif /*__BPF_CTX_XDP_H_*/

static __always_inline
    int __lb6_select_backend(struct lb6_key *key, const struct lb6_service *svc)
{
	// slave need recalc
	key->slave %= MAGLEV_RING_SIZE;
	return lb_select_backend(key->slave, svc->rev_nat_index);
}

static __always_inline
    int lb6_select_backend(struct __ctx_buff *ctx,
			   struct lb6_key *key, struct ipv6_ct_tuple *tuple,
			   const struct lb6_service *svc)
{
	int backend_id;

	cilium_dbg_lb(ctx, DBG_LB_LOOKUP_MAGLEV, svc->rev_nat_index,
		      key->dport);

	key->slave = get_tuple6_hash(ctx, tuple);
	if ((backend_id = __lb6_select_backend(key, svc)) == -1) {
		cilium_dbg_lb(ctx, DBG_LB_LOOKUP_MAGLEV_FAIL,
			      svc->rev_nat_index, key->dport);
	} else if (backend_id == -2) {
		cilium_dbg_lb(ctx, DBG_LB_LOOKUP_MAGLEV_OUTER_FAIL,
			      svc->rev_nat_index, key->dport);
	} else {
		cilium_dbg_lb(ctx, DBG_LB_LOOKUP_MAGLEV_SUCCESS,
			      svc->rev_nat_index, backend_id);
	}

	return backend_id;
}

#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4

#ifdef __BPF_CTX_XDP_H_

static __always_inline __u32 get_tuple4_hash(__attribute__((unused)) struct __ctx_buff *ctx,
					     struct ipv4_ct_tuple *tuple)
{
	return jhash_2words(tuple->saddr,
			    ((__u32) tuple->dport << 16) | tuple->sport,
			    INIT_JHASH_SEED);
}

#else /*!__BPF_CTX_XDP_H_ */

static __always_inline __u32 get_tuple4_hash(struct __ctx_buff *ctx,
					     __attribute__((unused)) struct ipv4_ct_tuple *tuple)
{
	return get_hash_recalc(ctx);
}

#endif /*__BPF_CTX_XDP_H_*/

static __always_inline
    int __lb4_select_backend(struct lb4_key *key, const struct lb4_service *svc)
{
	// slave need recalc
	key->slave %= MAGLEV_RING_SIZE;
	return lb_select_backend(key->slave, svc->rev_nat_index);
}

static __always_inline
    int lb4_select_backend(struct __ctx_buff *ctx,
			   struct lb4_key *key, struct ipv4_ct_tuple *tuple,
			   const struct lb4_service *svc)
{
	int backend_id;

	cilium_dbg_lb(ctx, DBG_LB_LOOKUP_MAGLEV, svc->rev_nat_index,
		      key->dport);

	key->slave = get_tuple4_hash(ctx, tuple);
	if ((backend_id = __lb4_select_backend(key, svc)) == -1) {
		cilium_dbg_lb(ctx, DBG_LB_LOOKUP_MAGLEV_FAIL,
			      svc->rev_nat_index, key->dport);
	} else if (backend_id == -2) {
		cilium_dbg_lb(ctx, DBG_LB_LOOKUP_MAGLEV_OUTER_FAIL,
			      svc->rev_nat_index, key->dport);
	} else {
		cilium_dbg_lb(ctx, DBG_LB_LOOKUP_MAGLEV_SUCCESS,
			      svc->rev_nat_index, backend_id);
	}

	return backend_id;
}

#endif /* ENABLE_IPV4 */

#endif /* __MAGLEV_H_ */
