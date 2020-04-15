/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_ETH__
#define __LIB_ETH__

#include <linux/if_ether.h>

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

union macaddr {
	struct {
		__u32 p1;
		__u16 p2;
	};
	__u8 addr[6];
};

static __always_inline int eth_addrcmp(const union macaddr *a,
				       const union macaddr *b)
{
	int tmp;

	tmp = a->p1 - b->p1;
	if (!tmp)
		tmp = a->p2 - b->p2;

	return tmp;
}

static __always_inline int eth_is_bcast(const union macaddr *a)
{
	union macaddr bcast;

	bcast.p1 = 0xffffffff;
	bcast.p2 = 0xffff;

	if (!eth_addrcmp(a, &bcast))
		return 1;
	else
		return 0;
}

static __always_inline int eth_load_saddr(struct __ctx_buff *ctx, __u8 *mac,
					  int off)
{
	return ctx_load_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN);
}

static __always_inline int eth_store_saddr(struct __ctx_buff *ctx, __u8 *mac,
					   int off)
{
	return ctx_store_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN, 0);
}

static __always_inline int eth_load_daddr(struct __ctx_buff *ctx, __u8 *mac,
					  int off)
{
	return ctx_load_bytes(ctx, off, mac, ETH_ALEN);
}

static __always_inline int eth_store_daddr(struct __ctx_buff *ctx, __u8 *mac,
					   int off)
{
	return ctx_store_bytes(ctx, off, mac, ETH_ALEN, 0);
}

static __always_inline int _eth_store_from_fib(struct __ctx_buff *ctx, struct bpf_fib_lookup *fib_params) {
	if (eth_store_daddr(ctx, fib_params->dmac, 0) < 0)
		return DROP_WRITE_ERROR;
	if (eth_store_saddr(ctx, fib_params->smac, 0) < 0)
		return DROP_WRITE_ERROR;
	return 0;
}

#endif /* __LIB_ETH__ */
