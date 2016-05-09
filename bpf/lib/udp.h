#ifndef __LIB_UDP_H_
#define __LIB_UDP_H_

#include <linux/udp.h>

#include "common.h"

#define UDP_DPORT_OFF (offsetof(struct udphdr, dest))
#define UDP_SPORT_OFF (offsetof(struct udphdr, source))
#define UDP_CSUM_OFF (offsetof(struct udphdr, check))

static inline void udp_modify_16(struct __sk_buff *skb, int off, __u16 port)
{
	__u16 old_port;

	skb_load_bytes(skb, off, &old_port, sizeof(old_port));
        l4_csum_replace(skb, UDP_CSUM_OFF, old_port, port, sizeof(port));
        skb_store_bytes(skb, off, &port, sizeof(port), 1);
}

/**
 * Store UDP destination port
 * @arg skb:  packet
 * @arg off:  offset to start of UDP header
 * @arg port: new port number
 *
 * Overwrites UDP destination port with new value and fixes up UDP checksum
 * and skb->csum accordingly.
 */
static inline void udp_store_dport(struct __sk_buff *skb, int off, __u16 port)
{
	udp_modify_16(skb, off + UDP_DPORT_OFF, port);
}

/**
 * Store UDP source port
 * @arg skb:  packet
 * @arg off:  offset to start of UDP header
 * @arg port: new port number
 *
 * Overwrites UDP source port with new value and fixes up UDP checksum
 * and skb->csum accordingly.
 */
static inline void udp_store_sport(struct __sk_buff *skb, int off, __u16 port)
{
	udp_modify_16(skb, off + UDP_SPORT_OFF, port);
}

static inline int udp_load_dport(struct __sk_buff *skb, int off, __u16 *port)
{
	return skb_load_bytes(skb, off + UDP_DPORT_OFF, port, sizeof(__u16));
}

static inline int udp_load_sport(struct __sk_buff *skb, int off, __u16 *port)
{
	return skb_load_bytes(skb, off + UDP_SPORT_OFF, port, sizeof(__u16));
}

#endif
