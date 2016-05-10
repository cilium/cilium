#ifndef __LIB_L3_H_
#define __LIB_L3_H_

#include "common.h"
#include "ipv6.h"
#include "eth.h"
#include "dbg.h"
#include "l4.h"
#include "lxc_map.h"
#include "icmp6.h"
#include "geneve.h"

/* validating options on tx is optional */
#define VALIDATE_GENEVE_TX

#ifdef ENCAP_IFINDEX
static inline int do_encapsulation(struct __sk_buff *skb, __u32 node_id,
				   __u32 seclabel, uint8_t *buf, int sz)
{
	struct bpf_tunnel_key key = {};
	int ret;

	key.tunnel_id = seclabel;
	key.remote_ipv4 = node_id;

#ifdef DEBUG_ENCAP
	printk("Encap to node %x, ifindex=%u, seclabel=0x%x\n",
		node_id, ENCAP_IFINDEX, seclabel);
#endif

	ret = skb_set_tunnel_key(skb, &key, sizeof(key), 0);
	if (unlikely(ret < 0))
		return TC_ACT_SHOT;

#ifdef ENCAP_GENEVE
	ret = skb_set_tunnel_opt(skb, buf, sz);
	if (unlikely(ret < 0))
		return TC_ACT_SHOT;
#ifdef VALIDATE_GENEVE_TX
	if (1) {
		struct geneveopt_val geneveopt_val = {};

		ret = parse_geneve_options(&geneveopt_val, buf);
		if (unlikely(ret < 0))
			return TC_ACT_SHOT;
	}
#endif /* VALIDATE_GENEVE_TX */

#ifdef DEBUG_GENEVE
	printk("set Geneve options of length %d\n", sz);
#endif

#endif /* ENCAP_GENEVE */

	return redirect(ENCAP_IFINDEX, 0);
}
#endif /* ENCAP_IFINDEX */

static inline int __inline__ __do_l3(struct __sk_buff *skb, int nh_off,
				     __u8 *smac, __u8 *dmac)
{

	if (ipv6_dec_hoplimit(skb, nh_off))
		return SEND_TIME_EXCEEDED;

	if (smac)
		eth_store_saddr(skb, smac, 0);

	eth_store_daddr(skb, dmac, 0);

	return TC_ACT_OK;
}

#ifndef DISABLE_PORT_MAP
static inline void map_lxc_in(struct __sk_buff *skb, int off,
			      struct lxc_info *lxc)
{
	__u8 nexthdr;
	int i;

	if (ipv6_load_nexthdr(skb, off, &nexthdr) < 0)
		return;

	off += sizeof(struct ipv6hdr);

#pragma unroll
	for (i = 0; i < PORTMAP_MAX; i++) {
		if (!lxc->portmap[i].to || !lxc->portmap[i].from)
			break;

		do_port_map_in(skb, off, nexthdr, &lxc->portmap[i]);
	}
}
#endif /* DISABLE_PORT_MAP */

static inline int __inline__ local_delivery(struct __sk_buff *skb, int nh_off,
					    union v6addr *dst, __u32 seclabel)
{
	struct lxc_info *dst_lxc;
	__u16 lxc_id = derive_lxc_id(dst);
	int ret;

#ifdef DEBUG_FLOW
	printk("Local L3 - lxc-id: %x\n", lxc_id);
#endif

	dst_lxc = map_lookup_elem(&cilium_lxc, &lxc_id);
	if (dst_lxc) {
		mac_t lxc_mac = dst_lxc->mac;
		mac_t router_mac = dst_lxc->node_mac;

		ret = __do_l3(skb, nh_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac);
		if (ret != TC_ACT_OK)
			return ret;

#ifndef DISABLE_PORT_MAP
		if (dst_lxc->portmap[0].to)
			map_lxc_in(skb, nh_off, dst_lxc);
#endif /* DISABLE_PORT_MAP */

#ifdef DEBUG_FLOW
		printk("L3 to ifindex %u ID: %d\n",
			dst_lxc->ifindex, ntohl(dst_lxc->sec_label));
#endif

		skb->cb[CB_SRC_LABEL] = seclabel;
		skb->cb[CB_IFINDEX] = dst_lxc->ifindex;

		tail_call(skb, &cilium_jmp, ntohl(dst_lxc->sec_label));
#ifdef DEBUG_POLICY
		printk("No policy program found, dropping\n");
#endif

		return TC_ACT_SHOT;
	} else {
#ifdef DEBUG_FLOW
		printk("No match\n");
#endif
	}

	return TC_ACT_UNSPEC;
}

#endif
