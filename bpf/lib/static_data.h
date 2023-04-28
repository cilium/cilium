/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_STATIC_DATA_H_
#define __LIB_STATIC_DATA_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "endian.h"

/* fetch_* macros assist in fetching variously sized static data */
#define fetch_u16(x) (__u16)__fetch(x)
#define fetch_u32(x) (__u32)__fetch(x)
#define fetch_u32_i(x, i) fetch_u32(x ## _ ## i)
#define fetch_u64(x) __fetch(x)
#define fetch_u64_i(x, i) fetch_u64(x ## _ ## i)
#define fetch_ipv6(x) fetch_u64_i(x, 1), fetch_u64_i(x, 2)
#define fetch_mac(x) { { fetch_u32_i(x, 1), (__u16)fetch_u32_i(x, 2) } }

/* DEFINE_* macros help to declare static data. */
#define DEFINE_U16(NAME, value) volatile __u16 NAME = value
#define DEFINE_U32(NAME, value) volatile __u32 NAME = value
#define DEFINE_U32_I(NAME, i) volatile __u32 NAME ## _ ## i
#define DEFINE_U64(NAME, value) volatile __u64 NAME = value
#define DEFINE_U64_I(NAME, i) volatile __u64 NAME ## _ ## i

#define DEFINE_IPV6(NAME, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16) \
DEFINE_U64_I(NAME, 1) = bpf_cpu_to_be64( \
			(__u64)(a1) << 56 | (__u64)(a2) << 48 | (__u64)(a3) << 40 | \
			(__u64)(a4) << 32 | (a5) << 24 | (a6) << 16 | (a7) << 8 | (a8)); \
DEFINE_U64_I(NAME, 2) = bpf_cpu_to_be64( \
			(__u64)(a9) << 56 | (__u64)(a10) << 48 | (__u64)(a11) << 40 | \
			(__u64)(a12) << 32 | (a13) << 24 | (a14) << 16 | (a15) << 8 | (a16));

#define DEFINE_MAC(NAME, a1, a2, a3, a4, a5, a6)			\
DEFINE_U32_I(NAME, 1) = (a1) << 24 | (a2) << 16 |  (a3) << 8 | (a4);	\
DEFINE_U32_I(NAME, 2) =                            (a5) << 8 | (a6)

#endif /* __LIB_STATIC_DATA_H_ */
