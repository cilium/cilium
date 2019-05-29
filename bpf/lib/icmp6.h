/*
 *  Copyright (C) 2016-2019 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#if !defined __LIB_ICMP6__ && defined ENABLE_IPV6
#define __LIB_ICMP6__

#include <linux/icmpv6.h>
#include <linux/in.h>
#include "common.h"
#include "eth.h"
#include "drop.h"

#define ICMP6_TYPE_OFFSET (sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_type))
#define ICMP6_CSUM_OFFSET (sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_cksum))
#define ICMP6_ND_TARGET_OFFSET (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))
#define ICMP6_ND_OPTS (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + sizeof(struct in6_addr))

/* If not specific action is specified, drop unknown neighbour solication
 * messages */
#ifndef ACTION_UNKNOWN_ICMP6_NS
#define ACTION_UNKNOWN_ICMP6_NS DROP_UNKNOWN_TARGET
#endif

static inline __u8 icmp6_load_type(struct __sk_buff *skb, int nh_off)
{
	__u8 type;
	skb_load_bytes(skb, nh_off + ICMP6_TYPE_OFFSET, &type, sizeof(type));
	return type;
}

static inline int __inline__ icmp6_send_reply(struct __sk_buff *skb, int nh_off)
{
	union macaddr smac, dmac = NODE_MAC;
	const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	union v6addr sip, dip, router_ip;
	__be32 sum;

	if (ipv6_load_saddr(skb, nh_off, &sip) < 0 ||
	    ipv6_load_daddr(skb, nh_off, &dip) < 0)
		return DROP_INVALID;

	BPF_V6(router_ip, ROUTER_IP);
	/* skb->saddr = skb->daddr */
	if (ipv6_store_saddr(skb, router_ip.addr, nh_off) < 0)
		return DROP_WRITE_ERROR;
	/* skb->daddr = skb->saddr */
	if (ipv6_store_daddr(skb, sip.addr, nh_off) < 0)
		return DROP_WRITE_ERROR;

	/* fixup checksums */
	sum = csum_diff(sip.addr, 16, router_ip.addr, 16, 0);
	if (l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	sum = csum_diff(dip.addr, 16, sip.addr, 16, 0);
	if (l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	/* dmac = smac, smac = dmac */
	if (eth_load_saddr(skb, smac.addr, 0) < 0)
		return DROP_INVALID;

	// eth_load_daddr(skb, dmac.addr, 0);
	if (eth_store_daddr(skb, smac.addr, 0) < 0 ||
	    eth_store_saddr(skb, dmac.addr, 0) < 0)
		return DROP_WRITE_ERROR;

	cilium_dbg_capture(skb, DBG_CAPTURE_DELIVERY, skb->ifindex);

	return redirect_self(skb);
}

static inline int __icmp6_send_echo_reply(struct __sk_buff *skb, int nh_off)
{
	struct icmp6hdr icmp6hdr = {}, icmp6hdr_old;
	int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	__be32 sum;

	cilium_dbg(skb, DBG_ICMP6_REQUEST, nh_off, 0);

	if (skb_load_bytes(skb, nh_off + sizeof(struct ipv6hdr), &icmp6hdr_old,
			   sizeof(icmp6hdr_old)) < 0)
		return DROP_INVALID;

	/* fill icmp6hdr */
	icmp6hdr.icmp6_type = 129;
	icmp6hdr.icmp6_code = 0;
	icmp6hdr.icmp6_cksum = icmp6hdr_old.icmp6_cksum;
	icmp6hdr.icmp6_dataun.un_data32[0] = 0;
	icmp6hdr.icmp6_identifier = icmp6hdr_old.icmp6_identifier;
	icmp6hdr.icmp6_sequence = icmp6hdr_old.icmp6_sequence;

	if (skb_store_bytes(skb, nh_off + sizeof(struct ipv6hdr), &icmp6hdr,
			    sizeof(icmp6hdr), 0) < 0)
		return DROP_WRITE_ERROR;

	/* fixup checksum */
	sum = csum_diff(&icmp6hdr_old, sizeof(icmp6hdr_old),
			&icmp6hdr, sizeof(icmp6hdr), 0);

	if (l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return icmp6_send_reply(skb, nh_off);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SEND_ICMP6_ECHO_REPLY) int tail_icmp6_send_echo_reply(struct __sk_buff *skb)
{
	int ret, nh_off = skb->cb[0];
	__u8 direction  = skb->cb[1];

	skb->cb[0] = 0;
	ret = __icmp6_send_echo_reply(skb, nh_off);
	if (IS_ERR(ret))
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, direction);

	return ret;
}

/*
 * icmp6_send_echo_reply
 * @skb:	socket buffer
 * @nh_off:	offset to the IPv6 header
 *
 * Send an ICMPv6 echo reply in return to an ICMPv6 echo reply.
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
static inline int icmp6_send_echo_reply(struct __sk_buff *skb, int nh_off,
					__u8 direction)
{
	skb->cb[0] = nh_off;
	skb->cb[1] = direction;
	ep_tail_call(skb, CILIUM_CALL_SEND_ICMP6_ECHO_REPLY);

	return DROP_MISSED_TAIL_CALL;
}

static inline int send_icmp6_ndisc_adv(struct __sk_buff *skb, int nh_off,
				       union macaddr *mac)
{
	struct icmp6hdr icmp6hdr = {}, icmp6hdr_old;
	__u8 opts[8], opts_old[8];
	const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	__be32 sum;

	if (skb_load_bytes(skb, nh_off + sizeof(struct ipv6hdr), &icmp6hdr_old,
			   sizeof(icmp6hdr_old)) < 0)
		return DROP_INVALID;

	/* fill icmp6hdr */
	icmp6hdr.icmp6_type = 136;
	icmp6hdr.icmp6_code = 0;
	icmp6hdr.icmp6_cksum = icmp6hdr_old.icmp6_cksum;
	icmp6hdr.icmp6_dataun.un_data32[0] = 0;
	icmp6hdr.icmp6_router = 1;
	icmp6hdr.icmp6_solicited = 1;
	icmp6hdr.icmp6_override = 0;

	if (skb_store_bytes(skb, nh_off + sizeof(struct ipv6hdr), &icmp6hdr, sizeof(icmp6hdr), 0) < 0)
		return DROP_WRITE_ERROR;

	/* fixup checksums */
	sum = csum_diff(&icmp6hdr_old, sizeof(icmp6hdr_old),
			&icmp6hdr, sizeof(icmp6hdr), 0);
	if (l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	/* get old options */
	if (skb_load_bytes(skb, nh_off + ICMP6_ND_OPTS, opts_old, sizeof(opts_old)) < 0)
		return DROP_INVALID;

	opts[0] = 2;
	opts[1] = 1;
	opts[2] = mac->addr[0];
	opts[3] = mac->addr[1];
	opts[4] = mac->addr[2];
	opts[5] = mac->addr[3];
	opts[6] = mac->addr[4];
	opts[7] = mac->addr[5];

	/* store ND_OPT_TARGET_LL_ADDR option */
	if (skb_store_bytes(skb, nh_off + ICMP6_ND_OPTS, opts, sizeof(opts), 0) < 0)
		return DROP_WRITE_ERROR;

	/* fixup checksum */
	sum = csum_diff(opts_old, sizeof(opts_old), opts, sizeof(opts), 0);
	if (l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return icmp6_send_reply(skb, nh_off);
}

static inline __be32 compute_icmp6_csum(char data[80], __u16 payload_len,
					struct ipv6hdr *ipv6hdr)
{
	__be32 sum;

	/* compute checksum with new payload length */
	sum = csum_diff(NULL, 0, data, payload_len, 0);
	//printk("csum1 = %x\n", sum);
	sum = ipv6_pseudohdr_checksum(ipv6hdr, IPPROTO_ICMPV6, payload_len,
				      sum);
	//printk("csum2 = %x\n", sum);

	return sum;
}

#ifdef HAVE_SKB_CHANGE_TAIL
static inline int __icmp6_send_time_exceeded(struct __sk_buff *skb, int nh_off)
{
	/* FIXME: Fix code below to not require this init */
        char data[80] = {};
        struct icmp6hdr *icmp6hoplim;
        struct ipv6hdr *ipv6hdr;
	char *upper; /* icmp6 or tcp or udp */
        const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
        __be32 sum = 0;
	__u16 payload_len = 0; /* FIXME: Uninit of this causes verifier bug */
	__u8 icmp6_nexthdr = IPPROTO_ICMPV6;
	int trimlen;

	/* initialize pointers to offsets in data */
	icmp6hoplim = (struct icmp6hdr *)data;
	ipv6hdr = (struct ipv6hdr *)(data + 8);
	upper = (data + 48);

        /* fill icmp6hdr */
        icmp6hoplim->icmp6_type = 3;
        icmp6hoplim->icmp6_code = 0;
        icmp6hoplim->icmp6_cksum = 0;
        icmp6hoplim->icmp6_dataun.un_data32[0] = 0;

	cilium_dbg(skb, DBG_ICMP6_TIME_EXCEEDED, 0, 0);

        /* read original v6 hdr into offset 8 */
        if (skb_load_bytes(skb, nh_off, ipv6hdr, sizeof(*ipv6hdr)) < 0)
		return DROP_INVALID;

	if (ipv6_store_nexthdr(skb, &icmp6_nexthdr, nh_off) < 0)
		return DROP_WRITE_ERROR;

        /* read original v6 payload into offset 48 */
        switch (ipv6hdr->nexthdr) {
        case IPPROTO_ICMPV6:
        case IPPROTO_UDP:
                if (skb_load_bytes(skb, nh_off + sizeof(struct ipv6hdr),
                                   upper, 8) < 0)
			return DROP_INVALID;
		sum = compute_icmp6_csum(data, 56, ipv6hdr);
		payload_len = bpf_htons(56);
		trimlen = 56 - bpf_ntohs(ipv6hdr->payload_len);
		if (skb_change_tail(skb, skb->len + trimlen, 0) < 0)
			return DROP_WRITE_ERROR;
		/* trim or expand buffer and copy data buffer after ipv6 header */
		if (skb_store_bytes(skb, nh_off + sizeof(struct ipv6hdr),
				    data, 56, 0) < 0)
			return DROP_WRITE_ERROR;
		if (ipv6_store_paylen(skb, nh_off, &payload_len) < 0)
			return DROP_WRITE_ERROR;

                break;
        /* copy header without options */
        case IPPROTO_TCP:
                if (skb_load_bytes(skb, nh_off + sizeof(struct ipv6hdr),
                                   upper, 20) < 0)
                        return DROP_INVALID;
		sum = compute_icmp6_csum(data, 68, ipv6hdr);
		payload_len = bpf_htons(68);
		/* trim or expand buffer and copy data buffer after ipv6 header */
		trimlen = 68 - bpf_ntohs(ipv6hdr->payload_len);
		if (skb_change_tail(skb, skb->len + trimlen, 0) < 0)
			return DROP_WRITE_ERROR;
		if (skb_store_bytes(skb, nh_off + sizeof(struct ipv6hdr),
				    data, 68, 0) < 0)
			return DROP_WRITE_ERROR;
		if (ipv6_store_paylen(skb, nh_off, &payload_len) < 0)
			return DROP_WRITE_ERROR;

                break;
        default:
                return DROP_UNKNOWN_L4;
        }

        if (l4_csum_replace(skb, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

        return icmp6_send_reply(skb, nh_off);
}
#endif

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED) int tail_icmp6_send_time_exceeded(struct __sk_buff *skb)
{
#ifdef HAVE_SKB_CHANGE_TAIL
	int ret, nh_off = skb->cb[0];
	__u8 direction  = skb->cb[1];

	skb->cb[0] = 0;
	ret = __icmp6_send_time_exceeded(skb, nh_off);
	if (IS_ERR(ret))
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, direction);

	return ret;
#else
	return 0;
#endif
}

/*
 * icmp6_send_time_exceeded
 * @skb:	socket buffer
 * @nh_off:	offset to the IPv6 header
 * @direction:  direction of packet (can be ingress or egress)
 * Send a ICMPv6 time exceeded in response to an IPv6 frame.
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
static inline int icmp6_send_time_exceeded(struct __sk_buff *skb, int nh_off, __u8 direction)
{
	skb->cb[0] = nh_off;
	skb->cb[1] = direction;

	ep_tail_call(skb, CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED);

	return DROP_MISSED_TAIL_CALL;
}

static inline int __icmp6_handle_ns(struct __sk_buff *skb, int nh_off)
{
	union v6addr target, router;

	if (skb_load_bytes(skb, nh_off + ICMP6_ND_TARGET_OFFSET, target.addr,
			   sizeof(((struct ipv6hdr *)NULL)->saddr)) < 0)
		return DROP_INVALID;

	cilium_dbg(skb, DBG_ICMP6_NS, target.p3, target.p4);

	BPF_V6(router, ROUTER_IP);
	if (ipv6_addrcmp(&target, &router) == 0) {
		union macaddr router_mac = NODE_MAC;

		return send_icmp6_ndisc_adv(skb, nh_off, &router_mac);
	} else {
		/* Unknown target address, drop */
		return ACTION_UNKNOWN_ICMP6_NS;
	}
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_HANDLE_ICMP6_NS) int tail_icmp6_handle_ns(struct __sk_buff *skb)
{
	int ret, nh_off = skb->cb[0];
	__u8 direction  = skb->cb[1];

	skb->cb[0] = 0;
	ret = __icmp6_handle_ns(skb, nh_off);
	if (IS_ERR(ret))
		return send_drop_notify_error(skb, 0, ret, TC_ACT_SHOT, direction);

	return ret;
}

/*
 * icmp6_handle_ns
 * @skb:	socket buffer
 * @nh_off:	offset to the IPv6 header
 * @direction:  direction of packet(ingress or egress)
 *
 * Respond to ICMPv6 Neighbour Solicitation
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
static inline int icmp6_handle_ns(struct __sk_buff *skb, int nh_off, __u8 direction)
{
	skb->cb[0] = nh_off;
	skb->cb[1] = direction;

	ep_tail_call(skb, CILIUM_CALL_HANDLE_ICMP6_NS);

	return DROP_MISSED_TAIL_CALL;
}

static inline int icmp6_handle(struct __sk_buff *skb, int nh_off,
			       struct ipv6hdr *ip6, __u8 direction)
{
	union v6addr router_ip;
	__u8 type = icmp6_load_type(skb, nh_off);

	cilium_dbg(skb, DBG_ICMP6_HANDLE, type, 0);
	BPF_V6(router_ip, ROUTER_IP);

	switch(type) {
	case 135:
		return icmp6_handle_ns(skb, nh_off, direction);
	case ICMPV6_ECHO_REQUEST:
		if (!ipv6_addrcmp((union v6addr *) &ip6->daddr, &router_ip))
			return icmp6_send_echo_reply(skb, nh_off, direction);
		break;
	}

	/* All branching above will have issued a tail call, all
	 * remaining traffic is subject to forwarding to containers.
	 */
	return 0;
}

#endif
