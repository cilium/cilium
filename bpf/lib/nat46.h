#ifndef __LIB_NAT46__
#define __LIB_NAT46__

#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include "common.h"
#include "ipv6.h"
#include "eth.h"
#include "dbg.h"

#define ENABLE_NAT46

static inline int get_csum_offset(__u8 protocol)
{
	int csum_off;

	switch (protocol) {
	case IPPROTO_TCP:
		csum_off = TCP_CSUM_OFF;
		break;
	case IPPROTO_UDP:
		csum_off = UDP_CSUM_OFF;
		break;
	case IPPROTO_ICMP:
		csum_off = (offsetof(struct icmphdr, checksum));
		break;
	case IPPROTO_ICMPV6:
		csum_off = (offsetof(struct icmp6hdr, icmp6_cksum));
		break;
	default:
		return TC_ACT_SHOT;
	}

	return csum_off;
}

static inline int icmp4_to_icmp6(struct __sk_buff *skb, int nh_off)
{
	struct icmphdr icmp4 = {};
	struct icmp6hdr icmp6 = {};
	__be32 csum = 0;

	if (skb_load_bytes(skb, nh_off, &icmp4, sizeof(icmp4)) < 0)
		return TC_ACT_SHOT;
	else
		icmp6.icmp6_cksum = icmp4.checksum;

	switch(icmp4.type) {
	case ICMP_ECHO:
		icmp6.icmp6_type = ICMPV6_ECHO_REQUEST;
		icmp6.icmp6_identifier = icmp4.un.echo.id;
		icmp6.icmp6_sequence = icmp4.un.echo.sequence;
		break;
	case ICMP_ECHOREPLY:
		icmp6.icmp6_type = ICMPV6_ECHO_REPLY;
		icmp6.icmp6_identifier = icmp4.un.echo.id;
		icmp6.icmp6_sequence = icmp4.un.echo.sequence;
		break;
	case ICMP_DEST_UNREACH:
		icmp6.icmp6_type = ICMPV6_DEST_UNREACH;
		switch(icmp4.code) {
		case ICMP_NET_UNREACH:
		case ICMP_HOST_UNREACH:
			icmp6.icmp6_code = ICMPV6_NOROUTE;
			break;
		case ICMP_PROT_UNREACH:
			icmp6.icmp6_type = ICMPV6_PARAMPROB;
			icmp6.icmp6_code = ICMPV6_UNK_NEXTHDR;
			icmp6.icmp6_pointer = 6;
			break;
		case ICMP_PORT_UNREACH:
			icmp6.icmp6_code = ICMPV6_PORT_UNREACH;
			break;
		case ICMP_FRAG_NEEDED:
			icmp6.icmp6_type = ICMPV6_PKT_TOOBIG;
			icmp6.icmp6_code = 0;
			/* FIXME */
			if (icmp4.un.frag.mtu)
				icmp6.icmp6_mtu = htonl(ntohs(icmp4.un.frag.mtu));
			else
				icmp6.icmp6_mtu = htonl(1500);
			break;
		case ICMP_SR_FAILED:
			icmp6.icmp6_code = ICMPV6_NOROUTE;
			break;
		case ICMP_NET_UNKNOWN:
		case ICMP_HOST_UNKNOWN:
		case ICMP_HOST_ISOLATED:
		case ICMP_NET_UNR_TOS:
		case ICMP_HOST_UNR_TOS:
			icmp6.icmp6_code = 0;
			break;
		case ICMP_NET_ANO:
		case ICMP_HOST_ANO:
		case ICMP_PKT_FILTERED:
			icmp6.icmp6_code = ICMPV6_ADM_PROHIBITED;
			break;
		default:
			return TC_ACT_SHOT;
		}
		break;
	case ICMP_TIME_EXCEEDED:
		icmp6.icmp6_type = ICMPV6_TIME_EXCEED;
		break;
	case ICMP_PARAMETERPROB:
		icmp6.icmp6_type = ICMPV6_PARAMPROB;
		/* FIXME */
		icmp6.icmp6_pointer = 6;
		break;
	default:
		return TC_ACT_SHOT;
	}

	skb_store_bytes(skb, nh_off, &icmp6, sizeof(icmp6), 0);

	icmp4.checksum = 0;
	icmp6.icmp6_cksum = 0;
	csum = csum_diff(&icmp4, sizeof(icmp4), &icmp6, sizeof(icmp6), 0);
	//printk("icmp46 csum_diff %x\n", csum);

	return csum;
}

static inline int icmp6_to_icmp4(struct __sk_buff *skb, int nh_off)
{
	struct icmphdr icmp4 = {};
	struct icmp6hdr icmp6 = {};
	__be32 csum = 0;

	if (skb_load_bytes(skb, nh_off, &icmp6, sizeof(icmp6)) < 0)
		return TC_ACT_SHOT;
	else
		icmp4.checksum = icmp6.icmp6_cksum;

	switch(icmp6.icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		icmp4.type = ICMP_ECHO;
		icmp4.un.echo.id = icmp6.icmp6_identifier;
		icmp4.un.echo.sequence = icmp6.icmp6_sequence;
		break;
	case ICMPV6_ECHO_REPLY:
		icmp4.type = ICMP_ECHOREPLY;
		icmp4.un.echo.id = icmp6.icmp6_identifier;
		icmp4.un.echo.sequence = icmp6.icmp6_sequence;
		break;
	case ICMPV6_DEST_UNREACH:
		icmp4.type = ICMP_DEST_UNREACH;
		switch(icmp6.icmp6_code) {
		case ICMPV6_NOROUTE:
		case ICMPV6_NOT_NEIGHBOUR:
		case ICMPV6_ADDR_UNREACH:
			icmp4.code = ICMP_HOST_UNREACH;
			break;
		case ICMPV6_ADM_PROHIBITED:
			icmp4.code = ICMP_HOST_ANO;
			break;
		case ICMPV6_PORT_UNREACH:
			icmp4.code = ICMP_PORT_UNREACH;
			break;
		default:
			return TC_ACT_SHOT;
		}
	case ICMPV6_PKT_TOOBIG:
		icmp4.type = ICMP_DEST_UNREACH;
		icmp4.code = ICMP_FRAG_NEEDED;
		/* FIXME */
		if (icmp6.icmp6_mtu)
			icmp4.un.frag.mtu = htons(ntohl(icmp6.icmp6_mtu));
		else
			icmp4.un.frag.mtu = htons(1500);
		break;
	case ICMPV6_TIME_EXCEED:
		icmp4.type = ICMP_TIME_EXCEEDED;
		icmp4.code = icmp6.icmp6_code;
		break;
	case ICMPV6_PARAMPROB:
		switch(icmp6.icmp6_code) {
		case ICMPV6_HDR_FIELD:
			icmp4.type = ICMP_PARAMETERPROB;
			icmp4.code = 0;
			break;
		case ICMPV6_UNK_NEXTHDR:
			icmp4.type = ICMP_DEST_UNREACH;
			icmp4.code = ICMP_PROT_UNREACH;
			break;
		default:
			return TC_ACT_SHOT;
		}
	default:
		return TC_ACT_SHOT;
	}

	skb_store_bytes(skb, nh_off, &icmp4, sizeof(icmp4), 0);

	icmp4.checksum = 0;
	icmp6.icmp6_cksum = 0;
	csum = csum_diff(&icmp6, sizeof(icmp6), &icmp4, sizeof(icmp4), 0);
	//printk("icmp64 csum_diff %x\n", csum);

	return csum;
}

static inline int ipv6_prefix_match(struct in6_addr *addr,
				    union v6addr *v6prefix)
{
	if (addr->in6_u.u6_addr32[0] == v6prefix->p1 &&
	    addr->in6_u.u6_addr32[1] == v6prefix->p2 &&
	    addr->in6_u.u6_addr32[2] == v6prefix->p3)
		return 1;
	else
		return 0;
}

/*
 * ipv4 to ipv6 stateless nat
 * (s4,d4) -> (s6,d6)
 * s6 = v6prefix_src<s4>
 * d6 = v6prefix_dst<d4>
 */
static inline int ipv4_to_ipv6(struct __sk_buff *skb, int nh_off,
			       union v6addr *v6prefix_src,
			       union v6addr *v6predix_dst)
{
	struct ipv6hdr v6 = {};
	struct iphdr v4 = {};
	int csum_off;
	int pushoff;
	__be32 csum = 0;
	__be16 v4hdr_len;
	__be16 protocol = htons(ETH_P_IPV6);
	__u64 csum_flags = BPF_F_PSEUDO_HDR;
	
	if (skb_load_bytes(skb, nh_off, &v4, sizeof(v4)) < 0)
		return TC_ACT_SHOT;

	/* build v6 header */
	v6.version = 0x6;
	v6.saddr.in6_u.u6_addr32[0] = v6prefix_src->p1;
	v6.saddr.in6_u.u6_addr32[1] = v6prefix_src->p2;
	v6.saddr.in6_u.u6_addr32[2] = v6prefix_src->p3;
	v6.saddr.in6_u.u6_addr32[3] = v4.saddr;

	v6.daddr.in6_u.u6_addr32[0] = v6predix_dst->p1;
	v6.daddr.in6_u.u6_addr32[1] = v6predix_dst->p2;
	v6.daddr.in6_u.u6_addr32[2] = v6predix_dst->p3;
	v6.daddr.in6_u.u6_addr32[3] = htonl((ntohl(v6predix_dst->p4) & 0xFFFF0000) | (ntohl(v4.daddr) & 0xFFFF));

	if (v4.protocol == IPPROTO_ICMP)
		v6.nexthdr = IPPROTO_ICMPV6;
	else
		v6.nexthdr = v4.protocol;
	v6.hop_limit = v4.ttl;
	v4hdr_len = (v4.ihl << 2);
	v6.payload_len = htons(ntohs(v4.tot_len) - v4hdr_len);

	pushoff = sizeof(struct ipv6hdr) - v4hdr_len;

	if (pushoff != 0 && skb_modify(skb, nh_off, pushoff, htons(ETH_P_IPV6),
				       BPF_F_HDR_OUTER_NET) < 0) {
		//printk("v46 NAT: skb_modify failed\n");
		return TC_ACT_SHOT;
	}

	skb_store_bytes(skb, nh_off, &v6, sizeof(v6), 0);
	skb_store_bytes(skb, nh_off - 2, &protocol, 2, 0);

	if (v4.protocol == IPPROTO_ICMP) {
		csum = icmp4_to_icmp6(skb, nh_off + sizeof(v6));
		csum = ipv6_pseudohdr_checksum(&v6, IPPROTO_ICMPV6,
					       ntohs(v6.payload_len), csum);
	} else {
		csum = csum_diff(&v4.saddr, 4, &v6.saddr, 16, csum);
		csum = csum_diff(&v4.daddr, 4, &v6.daddr, 16, csum);
		if (v4.protocol == IPPROTO_UDP)
			csum_flags |= BPF_F_MARK_MANGLED_0;
	}

	/* 
	 * get checksum from inner header tcp / udp / icmp
	 * undo ipv4 pseudohdr checksum and
	 * add  ipv6 pseudohdr checksum
	 */
	csum_off = get_csum_offset(v6.nexthdr);
	if (csum_off < 0)
		return TC_ACT_SHOT;
	else
		csum_off += sizeof(struct ipv6hdr);

	l4_csum_replace(skb, nh_off + csum_off, 0, csum, csum_flags);

	printk("v46 NAT: nh_off %d, pushoff %d, csum_off %d\n",
	       nh_off, pushoff, csum_off);

	return 0;
}

/*
 * ipv6 to ipv4 stateless nat
 * (s6,d6) -> (s4,d4)
 * s4 = <ipv4-range>.<lxc-id>
 * d4 = d6[96 .. 127]
 */
static inline int ipv6_to_ipv4(struct __sk_buff *skb, int nh_off,
			       union v6addr *v6prefix_dst,
			       __u32 saddr)
{
	struct ipv6hdr v6 = {};
	struct iphdr v4 = {};
	int pushoff = -20;
	int csum_off;
	__be32 csum = 0;
	__be16 protocol = htons(ETH_P_IP);
	__u64 csum_flags = BPF_F_PSEUDO_HDR;

	if (skb_load_bytes(skb, nh_off, &v6, sizeof(v6)) < 0)
		return TC_ACT_SHOT;

	if (!ipv6_prefix_match(&v6.daddr, v6prefix_dst)) {
		//printk("v64 nat dst prefix mismatch\n");
		return 0;
	}

	/* build v4 header */
	v4.ihl = 0x5;
	v4.version = 0x4;
	v4.saddr = saddr;
	v4.daddr = v6.daddr.in6_u.u6_addr32[3];
	if (v6.nexthdr == IPPROTO_ICMPV6)
		v4.protocol = IPPROTO_ICMP;
	else
		v4.protocol = v6.nexthdr;
	v4.ttl = v6.hop_limit;
	v4.tot_len = htons(ntohs(v6.payload_len) + sizeof(v4));
	csum_off = offsetof(struct iphdr, check);
	csum = csum_diff(NULL, 0, &v4, sizeof(v4), csum);

	if (skb_modify(skb, nh_off, pushoff, htons(ETH_P_IP),
		       BPF_F_HDR_OUTER_NET) < 0) {
		//printk("v46 NAT: skb_modify failed\n");
		return TC_ACT_SHOT;
	}

	skb_store_bytes(skb, nh_off, &v4, sizeof(v4), 0);
	skb_store_bytes(skb, nh_off - 2, &protocol, 2, 0);
	l3_csum_replace(skb, nh_off + csum_off, 0, csum, 0);

	if (v6.nexthdr == IPPROTO_ICMPV6) {
		__be32 csum1 = 0;
		csum = icmp6_to_icmp4(skb, nh_off + sizeof(v4));
		csum1 = ipv6_pseudohdr_checksum(&v6, IPPROTO_ICMPV6,
						ntohs(v6.payload_len), 0);
		csum = csum - csum1;
	} else {
		csum = 0;
		csum = csum_diff(&v6.saddr, 16, &v4.saddr, 4, csum);
		csum = csum_diff(&v6.daddr, 16, &v4.daddr, 4, csum);
		if (v4.protocol == IPPROTO_UDP)
			csum_flags |= BPF_F_MARK_MANGLED_0;
	}
	/* 
	 * get checksum from inner header tcp / udp / icmp
	 * undo ipv6 pseudohdr checksum and
	 * add  ipv4 pseudohdr checksum
	 */
	csum_off = get_csum_offset(v4.protocol);
	if (csum_off < 0)
		return TC_ACT_SHOT;
	else
		csum_off += sizeof(struct iphdr);

	l4_csum_replace(skb, nh_off + csum_off, 0, csum, csum_flags);

	printk("v64 NAT: nh_off %d, pushoff %d, csum_off %d\n",
	       nh_off, pushoff, csum_off);

	return 0;
}

#endif /* __LIB_NAT46__ */
