/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BACKEND_SELECTOR_H_
#define __BACKEND_SELECTOR_H_

#ifdef LB_DEBUG
#define cilium_dbg_lb cilium_dbg
#else
#define cilium_dbg_lb(a, b, c, d)
#endif /* LB_DEBUG */

#ifdef ENABLE_MAGLEV

#include "maglev.h"

#else /* !ENABLE_MAGLEV */

#ifdef ENABLE_IPV6

static __always_inline
    struct lb6_service *__lb6_lookup_slave(struct lb6_key *key)
{
	return map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
}

static __always_inline int lb6_select_slave(__u16 count)
{
	/* Slave 0 is reserved for the master slot */
	return (get_prandom_u32() % count) + 1;
}

static __always_inline
    int __lb6_select_backend(struct lb6_key *key, const struct lb6_service *svc)
{
	struct lb6_service *slave_svc;

	// slave need recalc
	key->slave = (key->slave % svc->count) + 1;
	if ((slave_svc = __lb6_lookup_slave(key)) != NULL) {
		return slave_svc->backend_id;
	}
	return -1;
}

static __always_inline
    int lb6_select_backend(__attribute__((unused)) struct __ctx_buff *ctx,
			   struct lb6_key *key, 
			   __attribute__((unused)) struct ipv6_ct_tuple *tuple, 
			   const struct lb6_service *svc)
{
	int backend_id;

	key->slave = lb6_select_slave(svc->count);
	cilium_dbg_lb(ctx, DBG_LB6_LOOKUP_SLAVE, key->slave, key->dport);

	if ((backend_id = __lb6_select_backend(key, svc)) == -1) {
		cilium_dbg_lb(ctx, DBG_LB6_LOOKUP_SLAVE_V2_FAIL, key->slave,
			      key->dport);
		goto end;
	}
end:
	return backend_id;
}

#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4

static __always_inline
    struct lb4_service *__lb4_lookup_slave(struct lb4_key *key)
{
	return map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
}

static __always_inline int lb4_select_slave(__u16 count)
{
	/* Slave 0 is reserved for the master slot */
	return (get_prandom_u32() % count) + 1;
}

static __always_inline
    int __lb4_select_backend(struct lb4_key *key, const struct lb4_service *svc)
{
	struct lb4_service *slave_svc;

	// slave need recalc
	key->slave = (key->slave % svc->count) + 1;
	if ((slave_svc = __lb4_lookup_slave(key)) != NULL) {
		return slave_svc->backend_id;
	}
	return -1;
}

static __always_inline
    int lb4_select_backend(__attribute__((unused)) struct __ctx_buff *ctx,
			   struct lb4_key *key, 
			   __attribute__((unused)) struct ipv4_ct_tuple *tuple, 
			   const struct lb4_service *svc)
{
	int backend_id;

	key->slave = lb4_select_slave(svc->count);
	cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_SLAVE, key->slave, key->dport);

	if ((backend_id = __lb4_select_backend(key, svc)) == -1) {
		cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_SLAVE_V2_FAIL, key->slave,
			      key->dport);
		goto end;
	}
end:
	return backend_id;
}

#endif /* ENABLE_IPV4 */

#endif /* ENABLE_MAGLEV */

#endif /* __BACKEND_SELECTOR_H_ */
