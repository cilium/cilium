/*
 *  Copyright (C) 2016-2017 Authors of Cilium
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
#ifndef __LIB_L4_H_
#define __LIB_L4_H_

#include <linux/tcp.h>
#include <linux/udp.h>
#include "common.h"
#include "dbg.h"
#include "csum.h"

#define TCP_DPORT_OFF (offsetof(struct tcphdr, dest))
#define TCP_SPORT_OFF (offsetof(struct tcphdr, source))
#define UDP_DPORT_OFF (offsetof(struct udphdr, dest))
#define UDP_SPORT_OFF (offsetof(struct udphdr, source))


/**
 * Modify L4 port and correct checksum
 * @arg skb:      packet
 * @arg l4_off:   offset to L4 header
 * @arg off:      offset from L4 header to source or destination port
 * @arg csum_off: offset from L4 header to 16bit checksum field in L4 header
 * @arg port:     new port value
 * @arg old_port: old port value (for checksum correction)
 *
 * Overwrites a TCP or UDP port with new value and fixes up the checksum
 * in the L4 header and of skb->csum.
 *
 * NOTE: Calling this function will invalidate any pkt context offset
 * validation for direct packet access.
 *
 * Return 0 on success or a negative DROP_* reason
 */
static inline int l4_modify_port(struct __sk_buff *skb, int l4_off, int off,
				 struct csum_offset *csum_off, __be16 port, __be16 old_port)
{
	if (csum_l4_replace(skb, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
		return DROP_CSUM_L4;

	if (skb_store_bytes(skb, l4_off + off, &port, sizeof(port), 0) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

static inline int l4_load_port(struct __sk_buff *skb, int off, __be16 *port)
{
        return skb_load_bytes(skb, off, port, sizeof(__be16));
}

/* Structure to define an L4 port which may ingress into an endpoint */
struct l4_allow
{
	/* Allowed destination port number */
	__be16 port;

	/* If defined, will redirect all traffic to this proxy port */
	__be16 proxy;

	/* Allowed nexthdr (IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP) */
	__u8 nexthdr;
};

#if (defined CFG_L3L4_INGRESS || defined CFG_L3L4_EGRESS) && !defined CONNTRACK
#error "CFG_L* requires CONNTRACK to be enabled"
#endif

/**
 * Perform L4 ingress proxyport lookup
 * @arg skb:	 packet
 * @arg dport:	 destination port (ingress port on endpoint)
 * @arg nexthdr: next header (IPPROTO_TCP, IPPROTO_UDP, ..)
 *
 * Returns: 0 if connection is allowed
 *          n > 0 if connection should be proxied to n
 */
static inline int __inline__
l4_ingress_proxy_lookup(struct __sk_buff *skb, __be16 dport, __u8 nexthdr)
{
#ifdef CFG_L3L4_INGRESS
	int allowed = DROP_POLICY_L4;

	BPF_L4_MAP(allowed, dport, nexthdr, CFG_L3L4_INGRESS);
	return allowed > 0 ? allowed : 0;
#else
	return 0;
#endif
}

/**
 * Perform L4 egress proxyport lookup
 * @arg skb:	 packet
 * @arg dport:	 egress destination port
 * @arg nexthdr: next header (IPPROTO_TCP, IPPROTO_UDP, ..)
 *
 * Returns: 0 if connection is allowed
 *          n > 0 if connection should be proxied to n
 */
static inline int __inline__
l4_egress_proxy_lookup(struct __sk_buff *skb, __be16 dport, __u8 nexthdr)
{
#ifdef CFG_L3L4_EGRESS
	int allowed = DROP_POLICY_L4;

	BPF_L4_MAP(allowed, dport, nexthdr, CFG_L3L4_EGRESS);
	return allowed > 0 ? allowed : 0;
#else
	return 0;
#endif
}

/**
 * Look up proxyport for L3-dependent L4 policy
 *
 * FIXME GH-2564: Replace L4 embedded map lookup with proxy_port in POLICY_MAP
 */
static inline int
l4_proxy_lookup(struct __sk_buff *skb, __u8 nh, __be16 dport, int dir)
{
	int proxy_port = 0;

	if (dir == CT_INGRESS) {
		if (nh == IPPROTO_UDP || nh == IPPROTO_TCP) {
			cilium_dbg(skb, DBG_GENERIC, dport, nh);
			proxy_port = l4_ingress_proxy_lookup(skb, dport, nh);
			if (unlikely(proxy_port < 0))
				return proxy_port;

			cilium_dbg(skb, DBG_L4_POLICY, proxy_port, CT_INGRESS);
		}
	} else {
		if (nh == IPPROTO_UDP || nh == IPPROTO_TCP) {
			proxy_port = l4_egress_proxy_lookup(skb, dport, nh);
			if (unlikely(proxy_port < 0))
				return proxy_port;

			cilium_dbg(skb, DBG_L4_POLICY, proxy_port, CT_EGRESS);
		}
	}

	return proxy_port;
}
#endif
