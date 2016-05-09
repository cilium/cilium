#define NODE_MAC { .addr = { 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde } }

#include <node_config.h>

#include <iproute2/bpf_api.h>

#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/ipv6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/geneve.h"

static inline int __inline__ do_l3_from_overlay(struct __sk_buff *skb, int nh_off, __u32 tunnel_id)
{
	union v6addr dst = {};
	__u32 node_id;

#ifdef DEBUG_FLOW
	printk("From overlay: skb %p len %d\n", skb, skb->len);
#endif

	ipv6_load_daddr(skb, nh_off, &dst);
	node_id = ipv6_derive_node_id(&dst);

	if (unlikely(node_id != NODE_ID)) {
#ifdef DEBUG_FLOW
		printk("Warning: Encaped framed received for node %x, dropping\n", node_id);
#endif

		return TC_ACT_SHOT;
	} else {
		return do_l3(skb, nh_off, &dst, ntohl(tunnel_id));
	}
}

__section("from-overlay")
int from_overlay(struct __sk_buff *skb)
{
	struct bpf_tunnel_key key = {};

	if (unlikely(skb_get_tunnel_key(skb, &key, sizeof(key), 0) < 0))
		return TC_ACT_SHOT;

#ifdef ENCAP_GENEVE
	if (1) {
		uint8_t buf[MAX_GENEVE_OPT_LEN] = {};
		struct geneveopt_val geneveopt_val = {};

		if (unlikely(skb_get_tunnel_opt(skb, buf, sizeof(buf)) < 0))
			return TC_ACT_SHOT;

		if (unlikely(parse_geneve_options(&geneveopt_val, buf) < 0))
			return TC_ACT_SHOT;
	}
#endif

	if (likely(skb->protocol == __constant_htons(ETH_P_IPV6)))
		return do_l3_from_overlay(skb, ETH_HLEN, key.tunnel_id);

	return TC_ACT_SHOT;
}
BPF_LICENSE("GPL");
