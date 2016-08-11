#ifndef __LIB_L4_H_
#define __LIB_L4_H_

#include <linux/tcp.h>
#include <linux/udp.h>
#include "common.h"
#include "dbg.h"

#define TCP_DPORT_OFF (offsetof(struct tcphdr, dest))
#define TCP_SPORT_OFF (offsetof(struct tcphdr, source))
#define TCP_CSUM_OFF (offsetof(struct tcphdr, check))
#define UDP_DPORT_OFF (offsetof(struct udphdr, dest))
#define UDP_SPORT_OFF (offsetof(struct udphdr, source))
#define UDP_CSUM_OFF (offsetof(struct udphdr, check))


/**
 * Return offset of L4 checksum field
 * @arg nexthdr:    Nexthdr value (IPPROTO_UDP or IPPROTO_TCP)
 */
static inline int l4_checksum_offset(__u8 nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
		return TCP_CSUM_OFF;

	case IPPROTO_UDP:
		return UDP_CSUM_OFF;
	}

	/* Ignore unknown L4 protocols */
	return 0;
}

/**
 * Modify L4 port and correct checksum
 * @arg skb:      packet
 * @arg off:      offset to L4 source or destination port
 * @arg csum_off: offset to 16bit checksum field in L4 header
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
static inline int l4_modify_port(struct __sk_buff *skb, int off, int csum_off,
				 __u16 port, __u16 old_port)
{
        if (l4_csum_replace(skb, csum_off, old_port, port, sizeof(port)) < 0)
		return DROP_CSUM_L4;

        if (skb_store_bytes(skb, off, &port, sizeof(port), 0) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

/**
 * Apply a port mapping for incoming packets
 * @arg skb:      packet
 * @arg l4_off:   offset to L4 header
 * @arg csum_off: offset to 16bit checksum field in L4 header
 * @arg map:      port mapping entry
 * @arg dport:    Current L4 destination port
 *
 * Checks if the packet needs to be port mapped and applies the mapping
 * if necessary.
 *
 * NOTE: Calling this function will invalidate any pkt context offset
 * validation for direct packet access.
 *
 * Return 0 on success or a negative DROP_* reason
 */
static inline int l4_port_map_in(struct __sk_buff *skb, int l4_off, int csum_off,
				 struct portmap *map, __u16 dport)
{
	cilium_trace(skb, DBG_PORT_MAP, ntohs(map->from), ntohs(map->to));

	if (likely(map->from != dport))
		return 0;

	/* Port offsets for UDP and TCP are the same */
	return l4_modify_port(skb, l4_off + TCP_DPORT_OFF, csum_off, map->to, dport);
}

/**
 * Apply a port mapping for outgoing packets
 * @arg skb:      packet
 * @arg l4_off:   offset to L4 header
 * @arg csum_off: offset to 16bit checksum field in L4 header
 * @arg map:      port mapping entry
 * @arg sport:    Current L4 source port
 *
 * Checks if the packet needs to be port mapped and applies the mapping
 * if necessary.
 *
 * NOTE: Calling this function will invalidate any pkt context offset
 * validation for direct packet access.
 *
 * Return 0 on success or a negative DROP_* reason
 */
static inline int l4_port_map_out(struct __sk_buff *skb, int l4_off, int csum_off,
				  struct portmap *map, __u16 sport)
{
	cilium_trace(skb, DBG_PORT_MAP, ntohs(map->to), ntohs(map->from));

	if (likely(map->to != sport))
		return 0;

	/* Port offsets for UDP and TCP are the same */
	return l4_modify_port(skb, l4_off + TCP_SPORT_OFF, csum_off, map->from, sport);
}

static inline int l4_load_port(struct __sk_buff *skb, int off, __u16 *port)
{
        return skb_load_bytes(skb, off, port, sizeof(__u16));
}

#endif
