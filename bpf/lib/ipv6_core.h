/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

union v6addr {
	__u8 addr[16];
	struct {
		__u32 p1;
		__u32 p2;
		__u32 p3;
		__u32 p4;
	} p;
#define p1 p.p1
#define p2 p.p2
#define p3 p.p3
#define p4 p.p4
	struct {
		__u64 d1;
		__u64 d2;
	} d;
#define d1 d.d1
#define d2 d.d2
} __packed;

static __always_inline void ipv6_addr_copy(union v6addr *dst,
					   const union v6addr *src)
{
	memcpy(dst, src, sizeof(*dst));
}

static __always_inline void ipv6_addr_copy_unaligned(union v6addr *dst,
						     const union v6addr *src)
{
	dst->d1 = src->d1;
	dst->d2 = src->d2;
}

static __always_inline bool ipv6_addr_equals(const union v6addr *a,
					     const union v6addr *b)
{
	if (a->d1 != b->d1)
		return false;
	return a->d2 == b->d2;
}
