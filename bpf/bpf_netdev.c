#include <node_config.h>
#include <netdev_config.h>

/* These are configuartion options which have a default value in their
 * respective header files and must thus be defined beforehand:
 *
 * Pass unknown ICMPv6 NS to stack */
#define ACTION_UNKNOWN_ICMP6_NS TC_ACT_OK

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/nat46.h"
#include "lib/arp.h"
#include "lib/policy.h"
#include "lib/drop.h"

static inline int is_node_subnet(const union v6addr *dst, const union v6addr *node_ip)
{
	int tmp;

	tmp = dst->p1 - node_ip->p1;
	if (!tmp) {
		tmp = dst->p2 - node_ip->p2;
		if (!tmp) {
			tmp = dst->p3 - node_ip->p3;
			if (!tmp) {
				__u32 a = ntohl(dst->p4);
				__u32 b = ntohl(node_ip->p4);
				tmp = (a & 0xFFFF0000) - (b & 0xFFFF0000);
			}
		}
	}

	return !tmp;
}

static inline int matches_cluster_prefix(const union v6addr *addr, const union v6addr *prefix)
{
	int tmp;

	tmp = addr->p1 - prefix->p1;
	if (!tmp) {
		tmp = addr->p2 - prefix->p2;
		if (!tmp) {
			__u32 a = ntohl(addr->p3);
			__u32 b = ntohl(prefix->p3);
			tmp = (a & 0xFFFF0000) - (b & 0xFFFF0000);
		}
	}

	return !tmp;
}

/*
 * respond to arp request for target IPV4_GATEWAY with HOST_IFINDEX_MAC
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_ARP) int tail_handle_arp(struct __sk_buff *skb)
{
	union macaddr mac = HOST_IFINDEX_MAC;
	return arp_respond(skb, &mac, IPV4_GATEWAY);
}

static inline __u32 derive_sec_ctx(struct __sk_buff *skb, const union v6addr *node_ip,
				   struct ipv6hdr *ip6)
{
#ifdef FIXED_SRC_SECCTX
	return FIXED_SRC_SECCTX;
#else
	if (matches_cluster_prefix((union v6addr *) &ip6->saddr, node_ip)) {
		/* Read initial 4 bytes of header and then extract flowlabel */
		__u32 *tmp = (__u32 *) ip6;
		return ntohl(*tmp & IPV6_FLOWLABEL_MASK);
	}

	return WORLD_ID;
#endif
}

static inline int handle_ipv6(struct __sk_buff *skb)
{
	union v6addr node_ip = { . addr = ROUTER_IP };
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;
	union v6addr *dst = (union v6addr *) &ip6->daddr;
	__u32 flowlabel;

	if (data + ETH_HLEN + sizeof(*ip6) > data_end)
		return DROP_INVALID;

#ifdef HANDLE_NS
	if (unlikely(ip6->nexthdr == IPPROTO_ICMPV6)) {
		int ret = icmp6_handle(skb, ETH_HLEN, ip6);
		if (IS_ERR(ret))
			return ret;
	}
#endif

	flowlabel = derive_sec_ctx(skb, &node_ip, ip6);

	if (likely(is_node_subnet(dst, &node_ip)))
		return ipv6_local_delivery(skb, ETH_HLEN, flowlabel, ip6);

	return TC_ACT_OK;
}

static inline __u32 derive_ipv4_sec_ctx(struct __sk_buff *skb, struct iphdr *ip4)
{
#ifdef FIXED_SRC_SECCTX
	return FIXED_SRC_SECCTX;
#else
	__u32 secctx = WORLD_ID;

	if ((ip4->saddr & IPV4_CLUSTER_MASK) == IPV4_CLUSTER_RANGE) {
		/* FIXME: Derive */
	}
	return secctx;
#endif
}

static inline int handle_ipv4(struct __sk_buff *skb)
{
	struct ipv4_ct_tuple tuple = {};
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;
	struct iphdr *ip4 = data + ETH_HLEN;
	__u32 secctx;
	int ret, l4_off;

	if (data + sizeof(*ip4) + ETH_HLEN > data_end)
		return DROP_INVALID;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	secctx = derive_ipv4_sec_ctx(skb, ip4);

	/* Check if destination is within our cluster prefix */
	if ((ip4->daddr & IPV4_MASK) == IPV4_RANGE) {
		tuple.nexthdr = ip4->protocol;
		ret = ipv4_local_delivery(skb, ETH_HLEN, l4_off, secctx, ip4);
		if (ret != DROP_NO_LXC)
			return ret;
	}

#ifdef ENABLE_NAT46
	if (1) {
		union v6addr sp = NAT46_SRC_PREFIX;
		union v6addr dp = HOST_IP;

		if (data + sizeof(*ip) + ETH_HLEN > data_end)
			return DROP_INVALID;

		if ((ip->daddr & IPV4_MASK) != IPV4_RANGE)
			return TC_ACT_OK;

		ret = ipv4_to_ipv6(skb, 14, &sp, &dp);
		if (IS_ERR(ret))
			return ret;

		proto = __constant_htons(ETH_P_IPV6);
		skb->tc_index = 1;
	}
#endif

	return TC_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4) int tail_handle_ipv4(struct __sk_buff *skb)
{
	int ret = handle_ipv4(skb);

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);

	return ret;
}

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	int ret;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_NETDEV, skb->ingress_ifindex);

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IPV6):
		/* This is considered the fast path, no tail call */
		ret = handle_ipv6(skb);
		break;

	case __constant_htons(ETH_P_IP):
		tail_call(skb, &cilium_calls, CILIUM_CALL_IPV4);
		ret = DROP_MISSED_TAIL_CALL;
		break;

#ifdef ENABLE_ARP_RESPONDER
	case __constant_htons(ETH_P_ARP):
		tail_call(skb, &cilium_calls, CILIUM_CALL_ARP);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif

	default:
		/* Pass unknown traffic to the stack */
		ret = TC_ACT_OK;
	}

	if (IS_ERR(ret))
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);
	else
		return ret;
}

__BPF_MAP(POLICY_MAP, BPF_MAP_TYPE_HASH, 0, sizeof(__u32),
	  sizeof(struct policy_entry), PIN_GLOBAL_NS, 1024);

__section_tail(CILIUM_MAP_POLICY, SECLABEL) int handle_policy(struct __sk_buff *skb)
{
	__u32 src_label = skb->cb[CB_SRC_LABEL];
	int ifindex = skb->cb[CB_IFINDEX];

	if (policy_can_access(&POLICY_MAP, skb, src_label) != TC_ACT_OK) {
		return send_drop_notify(skb, src_label, SECLABEL, 0,
					ifindex, TC_ACT_SHOT);
	} else {
		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, ifindex);

		/* ifindex 0 indicates passing down to the stack */
		if (ifindex == 0)
			return TC_ACT_OK;
		else
			return redirect(ifindex, 0);
	}
}

BPF_LICENSE("GPL");
