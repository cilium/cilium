/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __constant_cpu_to_be32(0x00800000),
	TCP_FLAG_ECE = __constant_cpu_to_be32(0x00400000),
	TCP_FLAG_URG = __constant_cpu_to_be32(0x00200000),
	TCP_FLAG_ACK = __constant_cpu_to_be32(0x00100000),
	TCP_FLAG_PSH = __constant_cpu_to_be32(0x00080000),
	TCP_FLAG_RST = __constant_cpu_to_be32(0x00040000),
	TCP_FLAG_SYN = __constant_cpu_to_be32(0x00020000),
	TCP_FLAG_FIN = __constant_cpu_to_be32(0x00010000),
	TCP_RESERVED_BITS = __constant_cpu_to_be32(0x0F000000),
	TCP_DATA_OFFSET = __constant_cpu_to_be32(0xF0000000)
}; 

/*
 * TCP general constants
 */
#define TCP_MSS_DEFAULT		 536U	/* IPv4 (RFC1122, RFC2581) */
#define TCP_MSS_DESIRED		1220U	/* IPv6 (tunneled), EDNS0 (RFC3226) */


#endif /* _LINUX_TCP_H */
