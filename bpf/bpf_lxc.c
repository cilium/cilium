#include <node_config.h>
#include <lxc_config.h>

#include <iproute2/bpf_api.h>

#include <linux/icmpv6.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/common.h"
#include "lib/ipv6.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/lxc.h"
#include "lib/nat46.h"
#include "lib/policy.h"
#include "lib/drop.h"
#include "lib/dbg.h"

__BPF_MAP(CT_MAP, BPF_MAP_TYPE_HASH, 0, sizeof(struct ipv6_ct_tuple),
	  sizeof(struct ipv6_ct_entry), PIN_GLOBAL_NS, CT_MAP_SIZE);

#ifndef DISABLE_PORT_MAP
static inline void map_lxc_out(struct __sk_buff *skb, int off)
{
	int i;
	__u8 nexthdr;
	struct portmap local_map[] = {
#ifdef LXC_PORT_MAPPINGS
		LXC_PORT_MAPPINGS
#endif
	};

	if (ipv6_load_nexthdr(skb, off, &nexthdr) < 0)
		return;

	off += sizeof(struct ipv6hdr);

#define NR_PORTMAPS (sizeof(local_map) / sizeof(local_map[0]))

#pragma unroll
	for (i = 0; i < NR_PORTMAPS; i++)
		do_port_map_out(skb, off, nexthdr, &local_map[i]);
}
#else
static inline void map_lxc_out(struct __sk_buff *skb, int off)
{
}
#endif /* DISABLE_PORT_MAP */

#ifdef ENCAP_IFINDEX
static inline int __inline__ lxc_encap(struct __sk_buff *skb, __u32 node_id)
{
#ifdef ENCAP_GENEVE
	uint8_t buf[] = GENEVE_OPTS;
#else
	uint8_t buf[] = {};
#endif
	return do_encapsulation(skb, node_id, SECLABEL_NB, buf, sizeof(buf));
}
#endif

static inline int __inline__ do_l3_from_lxc(struct __sk_buff *skb, int nh_off)
{
	union macaddr router_mac = NODE_MAC;
	union v6addr host_ip = HOST_IP;
	union v6addr dst = {};
	int do_nat46 = 0;

	if (unlikely(invalid_src_mac(skb)))
		return DROP_INVALID_SMAC;
	else if (unlikely(invalid_src_ip(skb, nh_off)))
		return DROP_INVALID_SIP;
	else if (unlikely(invalid_dst_mac(skb)))
		return DROP_INVALID_DMAC;

	ipv6_load_daddr(skb, nh_off, &dst);
	map_lxc_out(skb, nh_off);

	/* Pass all outgoing packets through conntrack. This will create an
	 * entry to allow reverse packets and return set cb[CB_POLICY] to
	 * POLICY_SKIP if the packet is a reply packet to an existing
	 * incoming connection. */
	skb->cb[CB_POLICY] = ct_create6_out(&CT_MAP, skb, ETH_HLEN, SECLABEL);
	if (skb->cb[CB_POLICY] == POLICY_DROP)
		return DROP_POLICY;

	/* Check if destination is within our cluster prefix */
	if (ipv6_match_subnet_96(&dst, &host_ip)) {
		__u32 node_id = ipv6_derive_node_id(&dst);

		if (node_id != NODE_ID) {
#ifdef ENCAP_IFINDEX
			return lxc_encap(skb, node_id);
#else
			/* Packets to other nodes are always allowed, the remote
			 * node will enforce the policy.
			 */
			policy_mark_skip(skb);
			goto pass_to_stack;
#endif
		}

#ifdef HOST_IFINDEX
		if (dst.addr[14] == host_ip.addr[14] &&
		    dst.addr[15] == host_ip.addr[15])
			goto to_host;
#endif

		return local_delivery(skb, nh_off, &dst, SECLABEL);
	} else {
#ifdef ENABLE_NAT46
		/* FIXME: Derive from prefix constant */
		if (unlikely((dst.p1 & 0xffff) == 0xadde)) {
			do_nat46 = 1;
			goto to_host;
		}
#endif

#ifdef ALLOW_TO_WORLD
		policy_mark_skip(skb);
#endif
		goto pass_to_stack;
	}

to_host:
	if (1) {
		union macaddr host_mac = HOST_IFINDEX_MAC;
		int ret;

		ret = __do_l3(skb, nh_off, (__u8 *) &router_mac.addr, (__u8 *) &host_mac.addr);
		if (ret != TC_ACT_OK)
			return ret;

		if (do_nat46) {
			union v6addr dp = NAT46_DST_PREFIX;

			if (ipv6_to_ipv4(skb, 14, &dp, IPV4_RANGE | (LXC_ID_NB <<16)) < 0)
				return TC_ACT_SHOT;
		}

#ifdef DISABLE_POLICY_ENFORCEMENT
		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, HOST_IFINDEX);
		return redirect(HOST_IFINDEX, 0);
#else
		skb->cb[CB_SRC_LABEL] = SECLABEL;
		skb->cb[CB_IFINDEX] = HOST_IFINDEX;

#ifdef ALLOW_TO_HOST
		policy_mark_skip(skb);
#endif

		tail_call(skb, &cilium_jmp, HOST_ID);
		cilium_trace(skb, DBG_NO_POLICY, HOST_ID, 0);
		return TC_ACT_SHOT;
#endif
	}

pass_to_stack:
	if (1) {
		int ret;

		ret = __do_l3(skb, nh_off, NULL, (__u8 *) &router_mac.addr);
		if (unlikely(ret != TC_ACT_OK))
			return ret;

		ipv6_store_flowlabel(skb, nh_off, SECLABEL_NB);
	}

#ifdef DISABLE_POLICY_ENFORCEMENT
	/* No policy, pass directly down to stack */
	cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, 0);
	return TC_ACT_OK;
#else
	skb->cb[CB_SRC_LABEL] = SECLABEL;
	skb->cb[CB_IFINDEX] = 0; /* Indicate passing to stack */

	tail_call(skb, &cilium_jmp, WORLD_ID);
	cilium_trace(skb, DBG_NO_POLICY, HOST_ID, 0);
	return TC_ACT_SHOT;
#endif
}

__section("from-container")
int handle_ingress(struct __sk_buff *skb)
{
	__u8 nexthdr;
	int ret;

	cilium_trace_capture(skb, DBG_CAPTURE_FROM_LXC, skb->ingress_ifindex);

	/* Drop all non IPv6 traffic */
	if (unlikely(skb->protocol != __constant_htons(ETH_P_IPV6)))
		return TC_ACT_SHOT;

	/* Handle ICMPv6 messages to the logical router, all other ICMPv6
	 * messages are passed on to the container (REDIRECT_TO_LXC)
	 */
	nexthdr = load_byte(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr));
	if (unlikely(nexthdr == IPPROTO_ICMPV6)) {
		ret = icmp6_handle(skb, ETH_HLEN);
		if (ret != REDIRECT_TO_LXC)
			goto error;
	}

	/* Perform L3 action on the frame */
	ret = do_l3_from_lxc(skb, ETH_HLEN);
error:
	if (likely(ret == TC_ACT_OK || ret == TC_ACT_REDIRECT))
		return ret;
	else if (ret == SEND_TIME_EXCEEDED)
		return icmp6_send_time_exceeded(skb, ETH_HLEN);
	else if (ret < 0 || ret == TC_ACT_SHOT) {
		if (ret < 0)
			ret = -ret;
		send_drop_notify_error(skb, ret);
		return TC_ACT_SHOT;
	} else {
		return ret;
	}
}

__BPF_MAP(POLICY_MAP, BPF_MAP_TYPE_HASH, 0, sizeof(__u32),
	  sizeof(struct policy_entry), PIN_GLOBAL_NS, 1024);

__section_tail(CILIUM_MAP_JMP, SECLABEL) int handle_policy(struct __sk_buff *skb)
{
	__u32 src_label = skb->cb[CB_SRC_LABEL];
	int ifindex = skb->cb[CB_IFINDEX];

	if (policy_can_access(&POLICY_MAP, skb, src_label) != TC_ACT_OK) {
		send_drop_notify(skb, src_label, SECLABEL, LXC_ID, ifindex);
		return TC_ACT_SHOT;
	} else {
		/* Create a connection tracking entry for any incoming traffic
		 * so egress traffic can be related.
		 */
		if (ct_create6_in(&CT_MAP, skb, ETH_HLEN, src_label) == POLICY_DROP) {
			send_drop_notify_error(skb, -(DROP_POLICY));
			return TC_ACT_SHOT;
		}

		cilium_trace_capture(skb, DBG_CAPTURE_DELIVERY, ifindex);
		return redirect(ifindex, 0);
	}
}

BPF_LICENSE("GPL");
