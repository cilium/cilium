/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ENDIAN_H_
#define __LIB_ENDIAN_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

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
# error "Endianness detection needs to be set up for your compiler?!"
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

#endif /* __LIB_ENDIAN_H_ */
