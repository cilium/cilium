#ifndef __LIB_L3_H_
#define __LIB_L3_H_

#include "common.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"
#include "l4.h"
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

	cilium_trace(skb, DBG_ENCAP, node_id, seclabel);

	ret = skb_set_tunnel_key(skb, &key, sizeof(key), 0);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;

#ifdef ENCAP_GENEVE
	ret = skb_set_tunnel_opt(skb, buf, sz);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;
#ifdef VALIDATE_GENEVE_TX
	if (1) {
		struct geneveopt_val geneveopt_val = {};

		ret = parse_geneve_options(&geneveopt_val, buf);
		if (IS_ERR(ret))
			return ret;
	}
#endif /* VALIDATE_GENEVE_TX */
#endif /* ENCAP_GENEVE */

	return redirect(ENCAP_IFINDEX, 0);
}
#endif /* ENCAP_IFINDEX */

static inline int __inline__ ipv6_l3(struct __sk_buff *skb, int nh_off,
				     __u8 *smac, __u8 *dmac)
{
	if (ipv6_dec_hoplimit(skb, nh_off))
		return icmp6_send_time_exceeded(skb, nh_off);

	if (smac)
		eth_store_saddr(skb, smac, 0);

	eth_store_daddr(skb, dmac, 0);

	return TC_ACT_OK;
}

static inline int __inline__ ipv4_l3(struct __sk_buff *skb, int l3_off,
				     __u8 *smac, __u8 *dmac, struct iphdr *ip4)
{
	if (ipv4_dec_ttl(skb, l3_off, ip4)) {
		/* FIXME: Send ICMP TTL */
		return DROP_INVALID;
	}

	if (smac)
		eth_store_saddr(skb, smac, 0);

	eth_store_daddr(skb, dmac, 0);

	return TC_ACT_OK;
}

#ifndef DISABLE_PORT_MAP
static inline int __inline__ map_lxc_in(struct __sk_buff *skb, int l4_off,
					struct lxc_info *lxc, __u8 nexthdr)
{
	int i;

#pragma unroll
	for (i = 0; i < PORTMAP_MAX; i++) {
		if (!lxc->portmap[i].to || !lxc->portmap[i].from)
			break;

		do_port_map_in(skb, l4_off, &lxc->portmap[i], nexthdr);
	}

	return 0;
}
#endif /* DISABLE_PORT_MAP */

static inline int ipv6_local_delivery(struct __sk_buff *skb, int nh_off,
				      union v6addr *dst, __u32 seclabel,
				      struct ipv6hdr *ip6)
{
	__u32 lxc_id = derive_lxc_id(dst);
	struct lxc_info *dst_lxc;
	int ret;

	cilium_trace(skb, DBG_LOCAL_DELIVERY, lxc_id, seclabel);

	dst_lxc = map_lookup_elem(&cilium_lxc, &lxc_id);
	if (dst_lxc) {
		mac_t lxc_mac = dst_lxc->mac;
		mac_t router_mac = dst_lxc->node_mac;
		__u8 nexthdr = ip6->nexthdr;

		/* This will invalidate the size check */
		ret = ipv6_l3(skb, nh_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac);
		if (ret != TC_ACT_OK)
			return ret;

#ifndef DISABLE_PORT_MAP
		if (dst_lxc->portmap[0].to) {
			ret = map_lxc_in(skb, nh_off + sizeof(*ip6), dst_lxc, nexthdr);
			if (IS_ERR(ret))
				return ret;
		}
#endif /* DISABLE_PORT_MAP */

		cilium_trace(skb, DBG_LXC_FOUND, dst_lxc->ifindex, ntohl(dst_lxc->sec_label));
		skb->cb[CB_SRC_LABEL] = seclabel;
		skb->cb[CB_IFINDEX] = dst_lxc->ifindex;

		tail_call(skb, &cilium_policy, ntohl(dst_lxc->sec_label));
		return DROP_MISSED_TAIL_CALL;
	}

	return DROP_NO_LXC;
}

static inline int __inline__ ipv4_local_delivery(struct __sk_buff *skb, int l3_off, int l4_off,
						 __u32 seclabel, struct iphdr *ip4)
{
	__u32 lxc_id = (ntohl(ip4->daddr) & 0xffff) | (1 << 16);
	struct lxc_info *dst_lxc;
	int ret;

	cilium_trace(skb, DBG_LOCAL_DELIVERY, lxc_id, seclabel);

	dst_lxc = map_lookup_elem(&cilium_lxc, &lxc_id);
	if (dst_lxc) {
		mac_t lxc_mac = dst_lxc->mac;
		mac_t router_mac = dst_lxc->node_mac;
		__u8 nexthdr = ip4->protocol;

		ret = ipv4_l3(skb, l3_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac, ip4);
		if (ret != TC_ACT_OK)
			return ret;

#ifndef DISABLE_PORT_MAP
		if (dst_lxc->portmap[0].to) {
			ret = map_lxc_in(skb, l4_off, dst_lxc, nexthdr);
			if (IS_ERR(ret))
				return ret;
		}
#endif /* DISABLE_PORT_MAP */

		cilium_trace(skb, DBG_LXC_FOUND, dst_lxc->ifindex, ntohl(dst_lxc->sec_label));
		skb->cb[CB_SRC_LABEL] = seclabel;
		skb->cb[CB_IFINDEX] = dst_lxc->ifindex;

		tail_call(skb, &cilium_policy, ntohl(dst_lxc->sec_label));
		return DROP_MISSED_TAIL_CALL;
	}

	return DROP_NO_LXC;
}

#endif
