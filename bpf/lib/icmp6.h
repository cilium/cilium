#ifndef __LIB_ICMP6__
#define __LIB_ICMP6__

#include <linux/icmpv6.h>
#include "common.h"
#include "eth.h"

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

static inline __be32 compute_icmp6_csum(char data[80], __u16 payload_len,
					struct ipv6hdr *ipv6hdr)
{
	__be32 sum = 0;

	/* compute checksum with new payload length */
	sum = csum_diff(NULL, 0, data, payload_len, 0);
	printk("csum1 = %x\n", sum);
	sum = ipv6_pseudohdr_checksum(ipv6hdr, IPPROTO_ICMPV6, payload_len,
				      sum);
	printk("csum2 = %x\n", sum);

	return sum;
}

static inline int send_icmp6_time_exceeded(struct __sk_buff *skb, int nh_off)
{
        char data[80] = {};
        struct icmp6hdr *icmp6hoplim;
        struct ipv6hdr *ipv6hdr;
	char *upper; /* icmp6 or tcp or udp */
        const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
        __be32 sum = 0;
	__u16 payload_len = 0;
	__u8 icmp6_nexthdr = IPPROTO_ICMPV6;

	/* initialize pointers to offsets in data */
	icmp6hoplim = (struct icmp6hdr *)data;
	ipv6hdr = (struct ipv6hdr *)(data + 8);
	upper = (data + 48);

        /* fill icmp6hdr */
        icmp6hoplim->icmp6_type = 3;
        icmp6hoplim->icmp6_code = 0;
        icmp6hoplim->icmp6_cksum = 0;
        icmp6hoplim->icmp6_dataun.un_data32[0] = 0;

        /* read original v6 hdr into offset 8 */
        if (skb_load_bytes(skb, nh_off, ipv6hdr, sizeof(*ipv6hdr)) < 0)
                return -1;

	if (ipv6_store_nexthdr(skb, &icmp6_nexthdr, nh_off) < 0)
		return -1;

        /* read original v6 payload into offset 48 */
        switch (ipv6hdr->nexthdr) {
        case IPPROTO_ICMPV6:
        case IPPROTO_UDP:
                if (skb_load_bytes(skb, nh_off + sizeof(struct ipv6hdr),
                                   upper, 8) < 0)
                        return -1;
		sum = compute_icmp6_csum(data, 56, ipv6hdr);
		payload_len = htons(56);
		/* trim or expand buffer and copy data buffer after ipv6 header */
		if (skb_modify_tail(skb, 56 - ntohs(ipv6hdr->payload_len)) < 0)
			return -1;
		if (skb_store_bytes(skb, nh_off + sizeof(struct ipv6hdr),
				    data, 56, 0) < 0)
			return -1;
		if (store_ipv6_paylen(skb, nh_off, &payload_len) < 0)
			return -1;

                break;
        /* copy header without options */
        case IPPROTO_TCP:
                if (skb_load_bytes(skb, nh_off + sizeof(struct ipv6hdr),
                                   upper, 20) < 0)
                        return -1;
		sum = compute_icmp6_csum(data, 68, ipv6hdr);
		payload_len = htons(68);
		/* trim or expand buffer and copy data buffer after ipv6 header */
		if (skb_modify_tail(skb, 68 - ntohs(ipv6hdr->payload_len)) < 0)
			return -1;
		if (skb_store_bytes(skb, nh_off + sizeof(struct ipv6hdr),
				    data, 68, 0) < 0)
			return -1;
		if (store_ipv6_paylen(skb, nh_off, &payload_len) < 0)
			return -1;

                break;
        default:
                return -1;
        }

        printk("IPv6 payload_len = %d, nexthdr %d, new payload_len %d\n",
               ntohs(ipv6hdr->payload_len), ipv6hdr->nexthdr, ntohs(payload_len));

        l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR);

        return send_icmp6_reply(skb, nh_off);
}

static inline int icmp6_handle_ns(struct __sk_buff *skb, int nh_off)
{
	union v6addr target = {}, router = { . addr = ROUTER_IP };

	if (skb_load_bytes(skb, nh_off + ICMP6_ND_TARGET_OFFSET, target.addr,
			   sizeof(((struct ipv6hdr *)NULL)->saddr)) < 0)
		return TC_ACT_SHOT;

	if (compare_ipv6_addr(&target, &router) == 0) {
		union macaddr router_mac = NODE_MAC;

		return send_icmp6_ndisc_adv(skb, nh_off, &router_mac);
	} else {
		/* Unknown target address, drop */
		return TC_ACT_SHOT;
	}
}

static inline int icmp6_handle(struct __sk_buff *skb, int nh_off)
{
	union v6addr dst = {};
	union v6addr router_ip = { .addr = ROUTER_IP };
	__u8 type = icmp6_load_type(skb, nh_off);
	int ret = TC_ACT_UNSPEC;

	printk("ICMPv6 packet skb %p len %d type %d\n", skb, skb->len, type);

	load_ipv6_daddr(skb, nh_off, &dst);

	switch(type) {
	case 135:
		ret = icmp6_handle_ns(skb, nh_off);
		break;
	case 128:
		if (!compare_ipv6_addr(&dst, &router_ip)) {
			ret = send_icmp6_echo_response(skb, nh_off);
			break;
		}
	case 129:
		ret = LXC_REDIRECT;
		break;
	default:
		break;
	}

	return ret;
}

#endif
