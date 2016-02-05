#ifndef __LIB_L4_H_
#define __LIB_L4_H_

#include "common.h"
#include "dbg.h"
#include "tcp.h"
#include "udp.h"

static inline void do_tcp_port_map_in(struct __sk_buff *skb, int off, 
				      struct portmap *map)
{
	__u16 dport = 0;

	tcp_load_dport(skb, off, &dport);

	printk("Comparing %u == %u\n", ntohs(map->from), ntohs(dport));

	if (map->from == dport)
		tcp_store_dport(skb, off, map->to);
}

static inline void do_udp_port_map_in(struct __sk_buff *skb, int off, 
				      struct portmap *map)
{
	__u16 dport = 0;

	udp_load_dport(skb, off, &dport);

	if (map->from == dport)
		udp_store_dport(skb, off, map->to);
}

static inline void do_port_map_in(struct __sk_buff *skb, int off, __u8 proto,
				  struct portmap *map)
{
	printk("Port map in: proto %u from: %u to: %u\n",
		proto, ntohs(map->from), ntohs(map->to));

	switch (proto) {
	case IPPROTO_TCP:
		do_tcp_port_map_in(skb, off, map);
		break;

	case IPPROTO_UDP:
		do_udp_port_map_in(skb, off, map);
		break;
	}
}

static inline void do_tcp_port_map_out(struct __sk_buff *skb, int off, 
				       struct portmap *map)
{
	__u16 sport = 0;

	tcp_load_sport(skb, off, &sport);

	printk("Comparing %u == %u\n", ntohs(map->to), ntohs(sport));

	if (map->to == sport)
		tcp_store_sport(skb, off, map->from);
}

static inline void do_udp_port_map_out(struct __sk_buff *skb, int off, 
				       struct portmap *map)
{
	__u16 sport = 0;

	udp_load_sport(skb, off, &sport);

	if (map->to == sport)
		udp_store_sport(skb, off, map->from);
}

static inline void do_port_map_out(struct __sk_buff *skb, int off, __u8 proto,
				   struct portmap *map)
{
	printk("Port map out: proto %u from: %u to: %u\n",
		proto, ntohs(map->from), ntohs(map->to));

	switch (proto) {
	case IPPROTO_TCP:
		do_tcp_port_map_out(skb, off, map);
		break;

	case IPPROTO_UDP:
		do_udp_port_map_out(skb, off, map);
		break;
	}
}

#endif
