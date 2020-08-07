/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_STATIC_DATA_H_
#define __LIB_STATIC_DATA_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "endian.h"

/* fetch_* macros assist in fetching variously sized static data */
#define fetch_u32(x) __fetch(x)
#define fetch_u32_i(x, i) __fetch(x ## _ ## i)
#define fetch_ipv6(x) fetch_u32_i(x, 1), fetch_u32_i(x, 2), fetch_u32_i(x, 3), fetch_u32_i(x, 4)
#define fetch_mac(x) { { fetch_u32_i(x, 1), (__u16)fetch_u32_i(x, 2) } }

/* DEFINE_* macros help to declare static data. */
#define DEFINE_U32(NAME, value) volatile __u32 NAME = value
#define DEFINE_U32_I(NAME, i) volatile __u32 NAME ## _ ## i
#define DEFINE_IPV6(NAME,									\
		    a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16)	\
DEFINE_U32_I(NAME, 1) = bpf_htonl( (a1) << 24 |  (a2) << 16 |  (a3) << 8 |  (a4));		\
DEFINE_U32_I(NAME, 2) = bpf_htonl( (a5) << 24 |  (a6) << 16 |  (a7) << 8 |  (a8));		\
DEFINE_U32_I(NAME, 3) = bpf_htonl( (a9) << 24 | (a10) << 16 | (a11) << 8 | (a12));		\
DEFINE_U32_I(NAME, 4) = bpf_htonl((a13) << 24 | (a14) << 16 | (a15) << 8 | (a16))

#define DEFINE_MAC(NAME, a1, a2, a3, a4, a5, a6)			\
DEFINE_U32_I(NAME, 1) = (a1) << 24 | (a2) << 16 |  (a3) << 8 | (a4);	\
DEFINE_U32_I(NAME, 2) =                            (a5) << 8 | (a6)

#endif /* __LIB_STATIC_DATA_H_ */
