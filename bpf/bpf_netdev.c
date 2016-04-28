#define NODE_MAC { .addr = { 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde } }

#include <node_config.h>

#include <iproute2/bpf_api.h>

#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/nat46.h"
#include "lib/arp.h"

#ifdef DROP_NOTIFY
#include "lib/drop.h"
#endif

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
 * respond to arp request for target IPV4_GW with HOST_IFINDEX_MAC
 */
__section_tail(CILIUM_MAP_PROTO, CILIUM_MAP_PROTO_ARP) int arp_respond(struct __sk_buff *skb)
{
	union macaddr mac = HOST_IFINDEX_MAC;
	__be32 ip = IPV4_GW;

	if (arp_prepare_response(skb, ip, &mac) != 0)
		return TC_ACT_SHOT;

	printk("arp_respond on ifindex %d\n", skb->ifindex);

	return redirect(skb->ifindex, 0);
}

static inline __u32 derive_sec_ctx(struct __sk_buff *skb, const union v6addr *node_ip)
{
#ifdef FIXED_SRC_SECCTX
	__u32 flowlabel = FIXED_SRC_SECCTX;
#else
	__u32 flowlabel = 0;
	union v6addr src = {};

	ipv6_load_saddr(skb, ETH_HLEN, &src);
	if (matches_cluster_prefix(&src, node_ip)) {
		ipv6_load_flowlabel(skb, ETH_HLEN, &flowlabel);
		flowlabel = ntohl(flowlabel);
	} else {
		flowlabel = WORLD_ID;
	}
#endif

	return flowlabel;
}


__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	union v6addr node_ip = { . addr = ROUTER_IP };

#ifdef ENABLE_ARP_RESPONDER
	union macaddr responder_mac = HOST_IFINDEX_MAC;
	if (unlikely(arp_check(skb, IPV4_GW, &responder_mac) == 1)) {
		tail_call(skb, &cilium_proto, CILIUM_MAP_PROTO_ARP);
		return TC_ACT_SHOT;
	}
#endif

#ifdef ENABLE_NAT46
	/* First try to do v46 nat */
	if (skb->protocol == __constant_htons(ETH_P_IP)) {
		union v6addr sp = NAT46_SRC_PREFIX;
		union v6addr dp = HOST_IP;
		__u32 dst = 0;

		if (ipv4_load_daddr(skb, ETH_HLEN, &dst) < 0)
			return TC_ACT_SHOT;

		if ((dst & IPV4_MASK) != IPV4_RANGE)
			return TC_ACT_OK;

		if (ipv4_to_ipv6(skb, 14, &sp, &dp) < 0) {
			printk("ipv4_to_ipv6 failed\n");
			return TC_ACT_SHOT;
		}
		skb->tc_index = 1;
	}
#endif

	if (likely(skb->protocol == __constant_htons(ETH_P_IPV6))) {
		union v6addr dst = {};
		__u32 flowlabel;

#ifdef HANDLE_NS
		__u8 nexthdr;

		nexthdr = load_byte(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr));
		if (unlikely(nexthdr == IPPROTO_ICMPV6)) {
			int ret = icmp6_handle(skb, ETH_HLEN);
			if (ret != REDIRECT_TO_LXC)
				return ret;
		}
#endif
		printk("IPv6 packet from netdev skb %p len %d\n", skb, skb->len);

		ipv6_load_daddr(skb, ETH_HLEN, &dst);
		flowlabel = derive_sec_ctx(skb, &node_ip);

		if (likely(is_node_subnet(&dst, &node_ip))) {
			printk("Targeted for a local container, src label: %d\n",
				ntohl(flowlabel));

			return do_l3(skb, ETH_HLEN, &dst, flowlabel);
		}
	}

	return TC_ACT_OK;
}

__BPF_MAP(POLICY_MAP, BPF_MAP_TYPE_HASH, 0, sizeof(__u32),
	  sizeof(struct policy_entry), PIN_GLOBAL_NS, 1024);

__section_tail(CILIUM_MAP_JMP, SECLABEL) int handle_policy(struct __sk_buff *skb)
{
	int ifindex = skb->cb[1];

#ifndef DISABLE_POCLIY_ENFORCEMENT
	struct policy_entry *policy;
	__u32 src_label = skb->cb[0];

	printk("Handle for host %d %d\n", ntohl(src_label), ifindex);

	policy = map_lookup_elem(&POLICY_MAP, &src_label);
	if (!policy) {
#ifdef DROP_NOTIFY
		send_drop_notify(skb, src_label, SECLABEL, 0, ifindex);
#endif
		printk("Denied by policy!\n");
#ifdef IGNORE_DROP
		return redirect(ifindex, 0);
#else
		return TC_ACT_SHOT;
#endif
	}
	__sync_fetch_and_add(&policy->packets, 1);
	__sync_fetch_and_add(&policy->bytes, skb->len);
#endif
	return redirect(ifindex, 0);
}

BPF_LICENSE("GPL");
