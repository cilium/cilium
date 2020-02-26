/*
 *  Copyright (C) 2016-2019 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __LIB_UTILS_H_
#define __LIB_UTILS_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#define min(x, y)		\
({				\
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x < _y ? _x : _y;	\
})

#define max(x, y)		\
({				\
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x > _y ? _x : _y;	\
})

#define NSEC_PER_SEC	1000000000UL

/* Monotonic clock, scalar format. */
static __always_inline __u64 bpf_ktime_get_nsec(void)
{
	return ktime_get_ns();
}

static __always_inline __u32 bpf_ktime_get_sec(void)
{
	/* Ignores remainder subtraction as we'd do in
	 * ns_to_timespec(), but good enough here.
	 */
	return (__u64)(bpf_ktime_get_nsec() / NSEC_PER_SEC);
}

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
	__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohs(x)		__builtin_bswap16(x)
# define __bpf_htons(x)		__builtin_bswap16(x)
# define __bpf_ntohl(x)		__builtin_bswap32(x)
# define __bpf_htonl(x)		__builtin_bswap32(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
	__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohs(x)		(x)
# define __bpf_htons(x)		(x)
# define __bpf_ntohl(x)		(x)
# define __bpf_htonl(x)		(x)
#else
# error "endianness detection needs to be set up for your compiler?!"
#endif

#define bpf_htons(x)				\
	(__builtin_constant_p(x) ?		\
	 __constant_htons(x) : __bpf_htons(x))
#define bpf_ntohs(x)				\
	(__builtin_constant_p(x) ?		\
	 __constant_ntohs(x) : __bpf_ntohs(x))

#define bpf_htonl(x)				\
	(__builtin_constant_p(x) ?		\
	 __constant_htonl(x) : __bpf_htonl(x))
#define bpf_ntohl(x)				\
	(__builtin_constant_p(x) ?		\
	 __constant_ntohl(x) : __bpf_ntohl(x))

/* fetch_* macros assist in fetching variously sized static data */
#define fetch_u32(x) __fetch(x)
#define fetch_u32_i(x, i) __fetch(x ## _ ## i)
#define fetch_ipv6(x) fetch_u32_i(x, 1), fetch_u32_i(x, 2), fetch_u32_i(x, 3), fetch_u32_i(x, 4)
#define fetch_mac(x) { { fetch_u32_i(x, 1), (__u16)fetch_u32_i(x, 2) } }

/* DEFINE_* macros help to declare static data. */
#define DEFINE_U32(NAME, value) __u32 NAME = value
#define DEFINE_U32_I(NAME, i) __u32 NAME ## _ ## i
#define DEFINE_IPV6(NAME, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16)	\
DEFINE_U32_I(NAME, 1) = bpf_htonl( (a1) << 24 |  (a2) << 16 |  (a3) << 8 |  (a4));			\
DEFINE_U32_I(NAME, 2) = bpf_htonl( (a5) << 24 |  (a6) << 16 |  (a7) << 8 |  (a8));			\
DEFINE_U32_I(NAME, 3) = bpf_htonl( (a9) << 24 | (a10) << 16 | (a11) << 8 | (a12));			\
DEFINE_U32_I(NAME, 4) = bpf_htonl((a13) << 24 | (a14) << 16 | (a15) << 8 | (a16))

#define DEFINE_MAC(NAME, a1, a2, a3, a4, a5, a6)			\
DEFINE_U32_I(NAME, 1) = (a1) << 24 | (a2) << 16 |  (a3) << 8 | (a4);	\
DEFINE_U32_I(NAME, 2) =                            (a5) << 8 | (a6)

#endif
