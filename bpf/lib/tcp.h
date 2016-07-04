#ifndef __LIB_TCP_H_
#define __LIB_TCP_H_

#include <linux/tcp.h>

#include "common.h"

#define TCP_DPORT_OFF (offsetof(struct tcphdr, dest))
#define TCP_SPORT_OFF (offsetof(struct tcphdr, source))
#define TCP_CSUM_OFF (offsetof(struct tcphdr, check))
#define TCP_FLAGS_OFF 12

static inline void tcp_modify_16(struct __sk_buff *skb, int off, __u16 port)
{
	__u16 old_port;

	skb_load_bytes(skb, off, &old_port, sizeof(old_port));
        l4_csum_replace(skb, TCP_CSUM_OFF, old_port, port, sizeof(port));

        skb_store_bytes(skb, off, &port, sizeof(port), 1);
}

/**
 * Store TCP destination port
 * @arg skb:  packet
 * @arg off:  offset to start of TCP header
 * @arg port: new port number
 *
 * Overwrites TCP destination port with new value and fixes up TCP checksum
 * and skb->csum accordingly.
 */
static inline void tcp_store_dport(struct __sk_buff *skb, int off, __u16 port)
{
	tcp_modify_16(skb, off + TCP_DPORT_OFF, port);
}

/**
 * Store TCP source port
 * @arg skb:  packet
 * @arg off:  offset to start of TCP header
 * @arg port: new port number
 *
 * Overwrites TCP source port with new value and fixes up TCP checksum
 * and skb->csum accordingly.
 */
static inline void tcp_store_sport(struct __sk_buff *skb, int off, __u16 port)
{
	tcp_modify_16(skb, off + TCP_SPORT_OFF, port);
}

#endif
