#ifndef __LIB_L4_H_
#define __LIB_L4_H_

#include "common.h"
#include "dbg.h"
#include "tcp.h"
#include "udp.h"

static inline void do_port_map_in(struct __sk_buff *skb, int off, struct portmap *map,
				  __u8 nexthdr)
{
	uint16_t dport;

#ifdef DEBUG_PORTMAP
	printk("Port map in: proto %u from: %u to: %u\n",
		nexthdr, ntohs(map->from), ntohs(map->to));
#endif

	if (skb_load_bytes(skb, off + 2, &dport, sizeof(dport)) < 0)
		return;

	switch (nexthdr) {
	case IPPROTO_TCP:
		if (map->from == dport)
			tcp_store_dport(skb, off, map->to);
		break;

	case IPPROTO_UDP:
		if (map->from == dport)
			udp_store_dport(skb, off, map->to);
		break;
	}
}

static inline void do_port_map_out(struct __sk_buff *skb, int off, struct portmap *map,
				   __u8 nexthdr)
{
	uint16_t sport;

#ifdef DEBUG_PORTMAP
	printk("Port map out: proto %u from: %u to: %u\n",
		nexthdr, ntohs(map->from), ntohs(map->to));
#endif

	if (skb_load_bytes(skb, off, &sport, sizeof(sport)) < 0)
		return;

	switch (nexthdr) {
	case IPPROTO_TCP:
		if (map->to == sport)
			tcp_store_sport(skb, off, map->from);
		break;

	case IPPROTO_UDP:
		if (map->to == sport)
			udp_store_sport(skb, off, map->from);
		break;
	}
}

#endif
