#ifndef __LIB_L4_H_
#define __LIB_L4_H_

#include "common.h"
#include "dbg.h"
#include "tcp.h"
#include "udp.h"

static inline void do_port_map_in(struct __sk_buff *skb, int off, struct ipv6hdr *ip6,
				  struct tcphdr *tcp, struct portmap *map)
{
#ifdef DEBUG_PORTMAP
	printk("Port map in: proto %u from: %u to: %u\n",
		ip6->nexthdr, ntohs(map->from), ntohs(map->to));
#endif

	switch (ip6->nexthdr) {
	case IPPROTO_TCP:
		if (map->from == tcp->dest)
			tcp_store_dport(skb, off, map->to);
		break;

	case IPPROTO_UDP:
		if (map->from == tcp->dest)
			udp_store_dport(skb, off, map->to);
		break;
	}
}

static inline void do_port_map_out(struct __sk_buff *skb, int off, __u8 proto,
				   struct portmap *map)
{
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	/* FIXME: extension headers */
	struct tcphdr *tcp = data + ETH_HLEN + sizeof(*ip6);

	if (data + ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(*tcp) > data_end)
		return;

#ifdef DEBUG_PORTMAP
	printk("Port map out: proto %u from: %u to: %u\n",
		ip6->nexthdr, ntohs(map->from), ntohs(map->to));
#endif

	switch (ip6->nexthdr) {
	case IPPROTO_TCP:
		if (map->to == tcp->source)
			tcp_store_sport(skb, off, map->from);
		break;

	case IPPROTO_UDP:
		if (map->to == tcp->source)
			udp_store_sport(skb, off, map->from);
		break;
	}
}

#endif
