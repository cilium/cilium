#include <node_config.h>
#include <netdev_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/geneve.h"
#include "lib/drop.h"

static inline int handle_ipv6(struct __sk_buff *skb)
{
	void *data_end = (void *) (long) skb->data_end;
	void *data = (void *) (long) skb->data;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	union v6addr *dst = (union v6addr *) &ip6->daddr;
	struct bpf_tunnel_key key = {};
	__u32 node_id;

	if (data + sizeof(*ip6) + ETH_HLEN > data_end)
		return DROP_INVALID;

	if (unlikely(skb_get_tunnel_key(skb, &key, sizeof(key), 0) < 0))
		return DROP_NO_TUNNEL_KEY;

#ifdef ENCAP_GENEVE
	if (1) {
		uint8_t buf[MAX_GENEVE_OPT_LEN] = {};
		struct geneveopt_val geneveopt_val = {};
		int ret;

		if (unlikely(skb_get_tunnel_opt(skb, buf, sizeof(buf)) < 0))
			return DROP_NO_TUNNEL_OPT;

		ret = parse_geneve_options(&geneveopt_val, buf);
		if (IS_ERR(ret))
			return ret;
	}
#endif

	node_id = ipv6_derive_node_id(dst);

	if (unlikely(node_id != NODE_ID))
		return DROP_NON_LOCAL;
	else
		return ipv6_local_delivery(skb, ETH_HLEN, dst, ntohl(key.tunnel_id), ip6);
}

static inline int handle_ipv4(struct __sk_buff *skb)
{
	void *data_end = (void *) (long) skb->data_end;
	void *data = (void *) (long) skb->data;
	struct iphdr *ip4 = data + ETH_HLEN;
	struct bpf_tunnel_key key = {};
	int l4_off;

	if (data + sizeof(*ip4) + ETH_HLEN > data_end)
		return DROP_INVALID;

	if (unlikely(skb_get_tunnel_key(skb, &key, sizeof(key), 0) < 0))
		return DROP_NO_TUNNEL_KEY;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	if (unlikely((ip4->daddr & IPV4_MASK) != IPV4_RANGE))
		return DROP_NON_LOCAL;
	else
		return ipv4_local_delivery(skb, ETH_HLEN, l4_off, key.tunnel_id, ip4);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4) int tail_handle_ipv4(struct __sk_buff *skb)
{
	int ret = handle_ipv4(skb);

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);

	return ret;
}

__section("from-overlay")
int from_overlay(struct __sk_buff *skb)
{
	int ret;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_OVERLAY, skb->ingress_ifindex);

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IPV6):
		/* This is considered the fast path, no tail call */
		ret = handle_ipv6(skb);
		break;

	case __constant_htons(ETH_P_IP):
		tail_call(skb, &cilium_calls, CILIUM_CALL_IPV4);
		ret = DROP_MISSED_TAIL_CALL;
		break;

	default:
		/* Pass unknown traffic to the stack */
		ret = TC_ACT_OK;
	}

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);
	else
		return ret;
}
BPF_LICENSE("GPL");
