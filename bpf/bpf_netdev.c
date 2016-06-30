#include <node_config.h>

#include <iproute2/bpf_api.h>

#include <sys/socket.h>

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
 * respond to arp request for target IPV4_GW with HOST_IFINDEX_MAC
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_ARP_RESPONDER) int arp_respond(struct __sk_buff *skb)
{
	union macaddr responder_mac = HOST_IFINDEX_MAC;

	if (unlikely(arp_check(skb, IPV4_GW, &responder_mac) == 1)) {
		union macaddr mac = HOST_IFINDEX_MAC;
		__be32 ip = IPV4_GW;
		int ret;

		ret = arp_prepare_response(skb, ip, &mac);
		if (unlikely(ret != 0))
			return send_drop_notify_error(skb, ret, TC_ACT_SHOT);

		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, skb->ifindex);
		return redirect(skb->ifindex, 0);
	}

	/* Pass any unknown ARP requests to the Linux stack */
	return TC_ACT_OK;
}

static inline __u32 derive_sec_ctx(struct __sk_buff *skb, const union v6addr *node_ip)
{
#ifdef FIXED_SRC_SECCTX
	return FIXED_SRC_SECCTX;
#else
	__u32 flowlabel = WORLD_ID;
	union v6addr src;

	ipv6_load_saddr(skb, ETH_HLEN, &src);
	if (matches_cluster_prefix(&src, node_ip)) {
		ipv6_load_flowlabel(skb, ETH_HLEN, &flowlabel);
		flowlabel = ntohl(flowlabel);
	}

	return flowlabel;
#endif
}


__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	union v6addr node_ip = { . addr = ROUTER_IP };
	__u32 proto = skb->protocol;
	int ret = TC_ACT_OK;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_NETDEV, skb->ingress_ifindex);

#ifdef ENABLE_ARP_RESPONDER
	if (unlikely(proto == __constant_htons(ETH_P_ARP))) {
		tail_call(skb, &cilium_calls, CILIUM_CALL_ARP_RESPONDER);
		ret = DROP_MISSED_TAIL_CALL;
		goto error;
	}
#endif

#ifdef ENABLE_NAT46
	/* First try to do v46 nat */
	if (proto == __constant_htons(ETH_P_IP)) {
		union v6addr sp = NAT46_SRC_PREFIX;
		union v6addr dp = HOST_IP;
		__u32 dst;

		if (ipv4_load_daddr(skb, ETH_HLEN, &dst) < 0) {
			ret = DROP_INVALID;
			goto error;
		}

		if ((dst & IPV4_MASK) != IPV4_RANGE)
			return TC_ACT_OK;

		ret = ipv4_to_ipv6(skb, 14, &sp, &dp);
		if (IS_ERR(ret))
			goto error;

		proto = __constant_htons(ETH_P_IPV6);
		skb->tc_index = 1;
	}
#endif

	if (likely(proto == __constant_htons(ETH_P_IPV6))) {
		union v6addr dst;
		__u32 flowlabel;

#ifdef HANDLE_NS
		__u8 nexthdr;

		nexthdr = load_byte(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr));
		if (unlikely(nexthdr == IPPROTO_ICMPV6)) {
			ret = icmp6_handle(skb, ETH_HLEN);
			if (IS_ERR(ret))
				goto error;
		}
#endif

		ipv6_load_daddr(skb, ETH_HLEN, &dst);
		flowlabel = derive_sec_ctx(skb, &node_ip);

		if (likely(is_node_subnet(&dst, &node_ip)))
			ret = local_delivery(skb, ETH_HLEN, &dst, flowlabel);
	}

	if (IS_ERR(ret)) {
error:
		return send_drop_notify_error(skb, ret, TC_ACT_SHOT);
	} else
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
