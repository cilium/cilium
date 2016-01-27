#ifndef __LIB_ICMP6__
#define __LIB_ICMP6__

#include <linux/icmpv6.h>
#include "common.h"
#include "eth.h"
#include "lxc_config.h"

#define ICMP6_TYPE_OFFSET (sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_type))
#define ICMP6_CSUM_OFFSET (sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_cksum))
#define ICMP6_ND_TARGET_OFFSET (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))
#define ICMP6_ND_OPTS (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + sizeof(struct in6_addr))

static inline __u8 icmp6_load_type(struct __sk_buff *skb, int nh_off)
{
	return load_byte(skb, nh_off + ICMP6_TYPE_OFFSET);
}

static inline int send_icmp6_reply(struct __sk_buff *skb, int nh_off)
{
	union macaddr smac = {}, dmac = NODE_MAC;
	const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	union v6addr sip = {}, dip = {};
	__be32 sum = 0;
	__u8 router_ip[] = ROUTER_IP;

	load_ipv6_saddr(skb, nh_off, &sip);
	load_ipv6_daddr(skb, nh_off, &dip);

	/* skb->saddr = skb->daddr  */
	store_ipv6_saddr(skb, router_ip, nh_off);
	/* skb->daddr = skb->saddr */
	store_ipv6_daddr(skb, sip.addr, nh_off);

	/* fixup checksums */
	sum = csum_diff(sip.addr, 16, router_ip, 16, 0);
	l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR);
	sum = csum_diff(dip.addr, 16, sip.addr, 16, 0);
	l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR);

	/* dmac = smac, smac = dmac */
	load_eth_saddr(skb, smac.addr, 0);
	// load_eth_daddr(skb, dmac.addr, 0);
	store_eth_daddr(skb, smac.addr, 0);
	store_eth_saddr(skb, dmac.addr, 0);

	printk("Redirect skb to Ifindex %d\n", skb->ifindex);

	return redirect(skb->ifindex, 0);
}

static inline int send_icmp6_echo_response(struct __sk_buff *skb, int nh_off)
{
	struct icmp6hdr icmp6hdr = {}, icmp6hdr_old = {};
	const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	__be32 sum = 0;

	if (skb_load_bytes(skb, nh_off + sizeof(struct ipv6hdr), &icmp6hdr_old,
			   sizeof(icmp6hdr_old)) < 0)
		return TC_ACT_SHOT;

	/* fill icmp6hdr */
	icmp6hdr.icmp6_type = 129;
	icmp6hdr.icmp6_code = 0;
	icmp6hdr.icmp6_cksum = icmp6hdr_old.icmp6_cksum;
	icmp6hdr.icmp6_dataun.un_data32[0] = 0;
	icmp6hdr.icmp6_identifier = icmp6hdr_old.icmp6_identifier;
	icmp6hdr.icmp6_sequence = icmp6hdr_old.icmp6_sequence;

	skb_store_bytes(skb, nh_off + sizeof(struct ipv6hdr), &icmp6hdr,
			sizeof(icmp6hdr), 0);

	/* fixup checksum */
	sum = csum_diff(&icmp6hdr_old, sizeof(icmp6hdr_old),
			&icmp6hdr, sizeof(icmp6hdr), 0);

	l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR);

	return send_icmp6_reply(skb, nh_off);
}

static inline int send_icmp6_ndisc_adv(struct __sk_buff *skb, int nh_off,
				       union macaddr *mac)
{
	struct icmp6hdr icmp6hdr = {}, icmp6hdr_old = {};
	__u8 opts[8] = { 2, 1, 0, 0, 0, 0, 0, 0 };
	__u8 opts_old[8] = {};
	const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	__be32 sum = 0;

	if (skb_load_bytes(skb, nh_off + sizeof(struct ipv6hdr), &icmp6hdr_old,
			   sizeof(icmp6hdr_old)) < 0)
		return TC_ACT_SHOT;

	/* fill icmp6hdr */
	icmp6hdr.icmp6_type = 136;
	icmp6hdr.icmp6_code = 0;
	icmp6hdr.icmp6_cksum = icmp6hdr_old.icmp6_cksum;
	icmp6hdr.icmp6_dataun.un_data32[0] = 0;
	icmp6hdr.icmp6_router = 1;
	icmp6hdr.icmp6_solicited = 1;
	icmp6hdr.icmp6_override = 0;

	skb_store_bytes(skb, nh_off + sizeof(struct ipv6hdr), &icmp6hdr, sizeof(icmp6hdr), 0);

	/* fixup checksums */
	sum = csum_diff(&icmp6hdr_old, sizeof(icmp6hdr_old),
			&icmp6hdr, sizeof(icmp6hdr), 0);
	l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR);

	/* get old options */
	if (skb_load_bytes(skb, nh_off + ICMP6_ND_OPTS, opts_old, sizeof(opts_old)) < 0)
		return TC_ACT_SHOT;

	opts[2] = mac->addr[0];
	opts[3] = mac->addr[1];
	opts[4] = mac->addr[2];
	opts[5] = mac->addr[3];
	opts[6] = mac->addr[4];
	opts[7] = mac->addr[5];

	/* store ND_OPT_TARGET_LL_ADDR option */
	skb_store_bytes(skb, nh_off + ICMP6_ND_OPTS, opts, sizeof(opts), 0);

	/* fixup checksum */
	sum = csum_diff(opts_old, sizeof(opts_old), opts, sizeof(opts), 0);
	l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR);

	return send_icmp6_reply(skb, nh_off);
}

#endif
