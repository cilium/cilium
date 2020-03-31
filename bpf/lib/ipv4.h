/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_IPV4__
#define __LIB_IPV4__

#include <linux/ip.h>

#include "dbg.h"

static __always_inline int ipv4_load_daddr(struct __ctx_buff *ctx, int off,
					   __u32 *dst)
{
	return ctx_load_bytes(ctx, off + offsetof(struct iphdr, daddr), dst, 4);
}

static __always_inline int ipv4_dec_ttl(struct __ctx_buff *ctx, int off,
					struct iphdr *ip4)
{
	__u8 new_ttl, ttl = ip4->ttl;

	if (ttl <= 1)
		return 1;

	new_ttl = ttl - 1;
	/* l3_csum_replace() takes at min 2 bytes, zero extended. */
	l3_csum_replace(ctx, off + offsetof(struct iphdr, check), ttl, new_ttl, 2);
	ctx_store_bytes(ctx, off + offsetof(struct iphdr, ttl), &new_ttl, sizeof(new_ttl), 0);

	return 0;
}

static __always_inline int ipv4_hdrlen(struct iphdr *ip4)
{
	return ip4->ihl * 4;
}

static __always_inline bool ipv4_is_fragment(struct iphdr *ip4)
{
	// The frag_off portion of the header consists of:
	//
	// +----+----+----+----------------------------------+
	// | RS | DF | MF | ...13 bits of fragment offset... |
	// +----+----+----+----------------------------------+
	//
	// If "More fragments" or the offset is nonzero, then this is an IP
	// fragment (RFC791).
	return ip4->frag_off & bpf_htons(0x3FFF);
}

#endif /* __LIB_IPV4__ */
