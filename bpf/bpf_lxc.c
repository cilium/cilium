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

#ifdef DROP_NOTIFY
#include "lib/drop.h"
#endif

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

#ifdef DEBUG_FLOW
	printk("From lxc: skb %p len %d\n", skb, skb->len);
#endif

	if (verify_src_mac(skb) || verify_src_ip(skb, nh_off) ||
	    verify_dst_mac(skb))
		return TC_ACT_SHOT;

	ipv6_load_daddr(skb, nh_off, &dst);
	map_lxc_out(skb, nh_off);

	/* Check if destination is within our cluster prefix */
	if (ipv6_match_subnet_96(&dst, &host_ip)) {
		__u32 node_id = ipv6_derive_node_id(&dst);

		if (node_id != NODE_ID) {
#ifdef ENCAP_IFINDEX
			return lxc_encap(skb, node_id);
#else
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
		return redirect(HOST_IFINDEX, 0);
#else
		skb->cb[0] = SECLABEL;
		skb->cb[1] = HOST_IFINDEX;

		tail_call(skb, &cilium_jmp, HOST_ID);
#ifdef DEBUG_POLICY
		printk("No policy program found, dropping packet to host\n");
#endif
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

	/* Pass down to stack */
	return TC_ACT_OK;
}

__section("from-container")
int handle_ingress(struct __sk_buff *skb)
{
	__u8 nexthdr;
	int ret;

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
			return ret;
	}

	/* Perform L3 action on the frame */
	switch ((ret = do_l3_from_lxc(skb, ETH_HLEN))) {
	case SEND_TIME_EXCEEDED:
		return icmp6_send_time_exceeded(skb, ETH_HLEN);
	default:
		return ret;
	}
}

__BPF_MAP(POLICY_MAP, BPF_MAP_TYPE_HASH, 0, sizeof(__u32),
	  sizeof(struct policy_entry), PIN_GLOBAL_NS, 1024);

__section_tail(CILIUM_MAP_JMP, SECLABEL) int handle_policy(struct __sk_buff *skb)
{
	int ifindex = skb->cb[1];

#ifndef DISABLE_POLICY_ENFORCEMENT
	struct policy_entry *policy;
	__u32 src_label = skb->cb[0];

	policy = map_lookup_elem(&POLICY_MAP, &src_label);
	if (unlikely(!policy)) {
#ifdef DROP_NOTIFY
		send_drop_notify(skb, src_label, SECLABEL, LXC_ID, ifindex);
#endif

#ifdef DEBUG_POLICY
		printk("Denied by policy! (%u->%u)\n", src_label, SECLABEL);
#endif

#ifndef IGNORE_DROP
		return TC_ACT_SHOT;
#endif
	} else {
		__sync_fetch_and_add(&policy->packets, 1);
		__sync_fetch_and_add(&policy->bytes, skb->len);
	}
#endif

	return redirect(ifindex, 0);
}

BPF_LICENSE("GPL");
