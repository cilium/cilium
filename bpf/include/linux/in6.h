/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
/*
 *	Types and definitions for AF_INET6 
 *	Linux INET6 implementation 
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>	
 *
 *	Sources:
 *	IPv6 Program Interfaces for BSD Systems
 *      <draft-ietf-ipngwg-bsd-api-05.txt>
 *
 *	Advanced Sockets API for IPv6
 *	<draft-stevens-advanced-api-00.txt>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_IN6_H
#define _LINUX_IN6_H

#include <linux/types.h>

/*
 *	IPv6 address structure
 */

struct in6_addr {
	union {
		__u8		u6_addr8[16];
		__be16		u6_addr16[8];
		__be32		u6_addr32[4];
	} in6_u;
#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
};

/*
 *	Bitmask constant declarations to help applications select out the 
 *	flow label and priority fields.
 *
 *	Note that this are in host byte order while the flowinfo field of
 *	sockaddr_in6 is in network byte order.
 */

#define IPV6_FLOWINFO_FLOWLABEL		0x000fffff
#define IPV6_FLOWINFO_PRIORITY		0x0ff00000

/* These definitions are obsolete */
#define IPV6_PRIORITY_UNCHARACTERIZED	0x0000
#define IPV6_PRIORITY_FILLER		0x0100
#define IPV6_PRIORITY_UNATTENDED	0x0200
#define IPV6_PRIORITY_RESERVED1		0x0300
#define IPV6_PRIORITY_BULK		0x0400
#define IPV6_PRIORITY_RESERVED2		0x0500
#define IPV6_PRIORITY_INTERACTIVE	0x0600
#define IPV6_PRIORITY_CONTROL		0x0700
#define IPV6_PRIORITY_8			0x0800
#define IPV6_PRIORITY_9			0x0900
#define IPV6_PRIORITY_10		0x0a00
#define IPV6_PRIORITY_11		0x0b00
#define IPV6_PRIORITY_12		0x0c00
#define IPV6_PRIORITY_13		0x0d00
#define IPV6_PRIORITY_14		0x0e00
#define IPV6_PRIORITY_15		0x0f00

/*
 *	IPV6 extension headers
 */
#define IPPROTO_HOPOPTS		0	/* IPv6 hop-by-hop options	*/
#define IPPROTO_ROUTING		43	/* IPv6 routing header		*/
#define IPPROTO_FRAGMENT	44	/* IPv6 fragmentation header	*/
#define IPPROTO_ICMPV6		58	/* ICMPv6			*/
#define IPPROTO_NONE		59	/* IPv6 no next header		*/
#define IPPROTO_DSTOPTS		60	/* IPv6 destination options	*/
#define IPPROTO_MH		135	/* IPv6 mobility header		*/

/*
 *	IPv6 TLV options.
 */
#define IPV6_TLV_PAD1		0
#define IPV6_TLV_PADN		1
#define IPV6_TLV_ROUTERALERT	5
#define IPV6_TLV_JUMBO		194
#define IPV6_TLV_HAO		201	/* home address option */

/*
 *	IPV6 socket options
 */
#define IPV6_ADDRFORM		1
#define IPV6_2292PKTINFO	2
#define IPV6_2292HOPOPTS	3
#define IPV6_2292DSTOPTS	4
#define IPV6_2292RTHDR		5
#define IPV6_2292PKTOPTIONS	6
#define IPV6_CHECKSUM		7
#define IPV6_2292HOPLIMIT	8
#define IPV6_NEXTHOP		9
#define IPV6_AUTHHDR		10	/* obsolete */
#define IPV6_FLOWINFO		11

#define IPV6_UNICAST_HOPS	16
#define IPV6_MULTICAST_IF	17
#define IPV6_MULTICAST_HOPS	18
#define IPV6_MULTICAST_LOOP	19
#define IPV6_ADD_MEMBERSHIP	20
#define IPV6_DROP_MEMBERSHIP	21
#define IPV6_ROUTER_ALERT	22
#define IPV6_MTU_DISCOVER	23
#define IPV6_MTU		24
#define IPV6_RECVERR		25
#define IPV6_V6ONLY		26
#define IPV6_JOIN_ANYCAST	27
#define IPV6_LEAVE_ANYCAST	28

/* IPV6_MTU_DISCOVER values */
#define IPV6_PMTUDISC_DONT		0
#define IPV6_PMTUDISC_WANT		1
#define IPV6_PMTUDISC_DO		2
#define IPV6_PMTUDISC_PROBE		3
/* same as IPV6_PMTUDISC_PROBE, provided for symetry with IPv4
 * also see comments on IP_PMTUDISC_INTERFACE
 */
#define IPV6_PMTUDISC_INTERFACE		4
/* weaker version of IPV6_PMTUDISC_INTERFACE, which allows packets to
 * get fragmented if they exceed the interface mtu
 */
#define IPV6_PMTUDISC_OMIT		5

/* Flowlabel */
#define IPV6_FLOWLABEL_MGR	32
#define IPV6_FLOWINFO_SEND	33

#define IPV6_IPSEC_POLICY	34
#define IPV6_XFRM_POLICY	35
#define IPV6_HDRINCL		36

/*
 * Multicast Routing:
 * see include/uapi/linux/mroute6.h.
 *
 * MRT6_BASE			200
 * ...
 * MRT6_MAX
 */
#endif /* _LINUX_IN6_H */
