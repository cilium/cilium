/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/compiler.h>
#include <bpf/builtins.h>
#include <bpf/helpers.h>

#include <lib/endian.h>
#include <lib/tunnel.h>

#include <linux/byteorder.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

/* A collection of pre-defined Ethernet MAC addresses, so tests can reuse them
 * without having to come up with custom addresses.
 *
 * These are declared as volatile const to make them end up in .rodata. Cilium
 * inlines global data from .data into bytecode as immediate values for compat
 * with kernels before 5.2 that lack read-only map support. This test suite
 * doesn't make the same assumptions, so disable the static data inliner by
 * putting variables in another section.
 */
static volatile const __u8 mac_one[] =   {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xEF};
static volatile const __u8 mac_two[] =   {0x13, 0x37, 0x13, 0x37, 0x13, 0x37};
static volatile const __u8 mac_three[] = {0x31, 0x41, 0x59, 0x26, 0x35, 0x89};
static volatile const __u8 mac_four[] =  {0x0D, 0x1D, 0x22, 0x59, 0xA9, 0xC2};
static volatile const __u8 mac_five[] =  {0x15, 0x21, 0x39, 0x45, 0x4D, 0x5D};
static volatile const __u8 mac_six[] =   {0x08, 0x14, 0x1C, 0x32, 0x52, 0x7E};
static volatile const __u8 mac_zero[] =  {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

/* A collection of pre-defined IP addresses, so tests can reuse them without
 *  having to come up with custom ips.
 */

#define IPV4(a, b, c, d) __bpf_htonl(((a) << 24) + ((b) << 16) + ((c) << 8) + (d))

/* IPv4 addresses for hosts, external to the cluster */
#define v4_ext_one	IPV4(110, 0, 11, 1)
#define v4_ext_two	IPV4(120, 0, 12, 2)
#define v4_ext_three	IPV4(130, 0, 13, 3)

/* IPv4 addresses for nodes in the cluster */
#define v4_node_one	IPV4(10, 0, 10, 1)
#define v4_node_two	IPV4(10, 0, 10, 2)
#define v4_node_three	IPV4(10, 0, 10, 3)

/* IPv4 addresses for services in the cluster */
#define v4_svc_one	IPV4(172, 16, 10, 1)
#define v4_svc_two	IPV4(172, 16, 10, 2)
#define v4_svc_three	IPV4(172, 16, 10, 3)

/* IPv4 addresses for pods in the cluster */
#define v4_pod_one	IPV4(192, 168, 0, 1)
#define v4_pod_two	IPV4(192, 168, 0, 2)
#define v4_pod_three	IPV4(192, 168, 0, 3)

#define v4_all	IPV4(0, 0, 0, 0)

/* IPv6 addresses for pods in the cluster */
static volatile const __section(".rodata") __u8 v6_pod_one[] = {0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 1};
static volatile const __section(".rodata") __u8 v6_pod_two[] = {0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 2};
static volatile const __section(".rodata") __u8 v6_pod_three[] = {0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 3};

/* IPv6 addresses for nodes in the cluster */
static volatile const __section(".rodata") __u8 v6_node_one[] = {0xfd, 0x05, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 1};
static volatile const __section(".rodata") __u8 v6_node_two[] = {0xfd, 0x06, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 2};
static volatile const __section(".rodata") __u8 v6_node_three[] = {0xfd, 0x07, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 3};

/* Source port to be used by a client */
#define tcp_src_one	__bpf_htons(22330)
#define tcp_src_two	__bpf_htons(33440)
#define tcp_src_three	__bpf_htons(44550)

#define tcp_dst_one	__bpf_htons(22331)
#define tcp_dst_two	__bpf_htons(33441)
#define tcp_dst_three	__bpf_htons(44551)

#define tcp_svc_one	__bpf_htons(80)
#define tcp_svc_two	__bpf_htons(443)
#define tcp_svc_three	__bpf_htons(53)

#define default_data "Should not change!!"

#define NEXTHDR_HOP             0       /* Hop-by-hop option header. */
#define NEXTHDR_TCP             6       /* TCP segment. */
#define NEXTHDR_UDP             17      /* UDP message. */
#define NEXTHDR_IPV6            41      /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING         43      /* Routing header. */
#define NEXTHDR_FRAGMENT        44      /* Fragmentation/reassembly header. */
#define NEXTHDR_GRE             47      /* GRE header. */
#define NEXTHDR_ESP             50      /* Encapsulating security payload. */
#define NEXTHDR_AUTH            51      /* Authentication header. */
#define NEXTHDR_ICMP            58      /* ICMP for IPv6. */
#define NEXTHDR_NONE            59      /* No next header */
#define NEXTHDR_DEST            60      /* Destination options header. */
#define NEXTHDR_SCTP            132     /* SCTP message. */
#define NEXTHDR_MOBILITY        135     /* Mobility header. */

#define NEXTHDR_MAX             255

/* Define SCTP header here because this is all we need. */
struct sctphdr {
	__be16 source;
	__be16 dest;
	__be32 vtag;
	__le32 checksum;
};

/* Define Ethernet variant ARP header */
struct arphdreth {
	__be16		ar_hrd;		  /* format of hardware address	*/
	__be16		ar_pro;		  /* format of protocol address	*/
	unsigned char	ar_hln;		  /* length of hardware address	*/
	unsigned char	ar_pln;		  /* length of protocol address	*/
	__be16		ar_op;		  /* ARP opcode (command)	*/
	unsigned char	ar_sha[ETH_ALEN]; /* source ethernet address	*/
	__be32		ar_sip;		  /* source IPv4 address	*/
	unsigned char	ar_tha[ETH_ALEN]; /* target ethernet address	*/
	__be32		ar_tip;		  /* target IPv4 address	*/
} __packed;

enum pkt_layer {
	PKT_LAYER_NONE,

	/* L2 layers */
	PKT_LAYER_ETH,
	PKT_LAYER_8021Q,

	/* L3 layers */
	PKT_LAYER_IPV4,
	PKT_LAYER_IPV6,
	PKT_LAYER_ARP,

	/* IPv6 extension headers */
	PKT_LAYER_IPV6_HOP_BY_HOP,
	PKT_LAYER_IPV6_AUTH,
	PKT_LAYER_IPV6_DEST,

	/* L4 layers */
	PKT_LAYER_TCP,
	PKT_LAYER_UDP,
	PKT_LAYER_ICMP,
	PKT_LAYER_ICMPV6,
	PKT_LAYER_SCTP,
	PKT_LAYER_ESP,

	/* Tunnel layers */
	PKT_LAYER_GENEVE,
	PKT_LAYER_VXLAN,

	/* Packet data*/
	PKT_LAYER_DATA,
};

#define IPV6_DEFAULT_HOPLIMIT 64

/* 3 outer headers + {VXLAN, GENEVE} + 3 inner headers. */
#define PKT_BUILDER_LAYERS 7

#define MAX_PACKET_OFF 0xffff

/* Packet builder */
struct pktgen {
	struct __ctx_buff *ctx;
	__u64 cur_off;
	__u64 layer_offsets[PKT_BUILDER_LAYERS];
	enum pkt_layer layers[PKT_BUILDER_LAYERS];
};

static __always_inline
void pktgen__init(struct pktgen *builder, struct __ctx_buff *ctx)
{
	builder->cur_off = 0;
	builder->ctx = ctx;
	#pragma unroll
	for (int i = 0; i < PKT_BUILDER_LAYERS; i++) {
		builder->layers[i] = PKT_LAYER_NONE;
		builder->layer_offsets[i] = 0;
	}
};

static __always_inline
int pktgen__free_layer(const struct pktgen *builder)
{
	#pragma unroll
	for (int i = 0; i < PKT_BUILDER_LAYERS; i++) {
		if (builder->layers[i] == PKT_LAYER_NONE)
			return i;
	}

	return -1;
}

static __always_inline
__attribute__((warn_unused_result))
void *pktgen__push_rawhdr(struct pktgen *builder, __u32 hdrsize, enum pkt_layer type)
{
	struct __ctx_buff *ctx = builder->ctx;
	void *layer = NULL;
	int layer_idx;

	/* Request additional tailroom, and check that we got it. */
	ctx_adjust_troom(ctx, builder->cur_off + hdrsize - ctx_full_len(ctx));
	if (ctx_data(ctx) + builder->cur_off + hdrsize > ctx_data_end(ctx))
		return NULL;

	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (builder->cur_off >= MAX_PACKET_OFF - hdrsize)
		return NULL;

	layer = ctx_data(ctx) + builder->cur_off;
	if ((void *)layer + hdrsize > ctx_data_end(ctx))
		return NULL;

	layer_idx = pktgen__free_layer(builder);
	if (layer_idx < 0)
		return NULL;

	builder->layers[layer_idx] = type;
	builder->layer_offsets[layer_idx] = builder->cur_off;
	builder->cur_off += hdrsize;

	return layer;
}

/* Push an empty ethernet header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct ethhdr *pktgen__push_ethhdr(struct pktgen *builder)
{
	return pktgen__push_rawhdr(builder, sizeof(struct ethhdr), PKT_LAYER_ETH);
}

/* helper to set the source and destination mac address at the same time */
static __always_inline
void ethhdr__set_macs(struct ethhdr *l2, unsigned char *src, unsigned char *dst)
{
	memcpy(l2->h_source, src, ETH_ALEN);
	memcpy(l2->h_dest, dst, ETH_ALEN);
}

/* Push an empty IPv4 header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct iphdr *pktgen__push_iphdr(struct pktgen *builder, __u32 option_bytes)
{
	__u32 length = sizeof(struct iphdr) + option_bytes;

	if (option_bytes > MAX_IPOPTLEN)
		return 0;

	return pktgen__push_rawhdr(builder, length, PKT_LAYER_IPV4);
}

/* helper to set the source and destination ipv6 address at the same time */
static __always_inline
void ipv6hdr__set_addrs(struct ipv6hdr *l3, __u8 *src, __u8 *dst)
{
	memcpy((__u8 *)&l3->saddr, src, 16);
	memcpy((__u8 *)&l3->daddr, dst, 16);
}

static __always_inline
__attribute__((warn_unused_result))
struct ipv6hdr *pktgen__push_ipv6hdr(struct pktgen *builder)
{
	return pktgen__push_rawhdr(builder, sizeof(struct ipv6hdr), PKT_LAYER_IPV6);
}

/* Push a IPv4 header with sane defaults and options onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct iphdr *pktgen__push_default_iphdr_with_options(struct pktgen *builder,
						      __u8 option_words)
{
	__u32 length = option_words * 4;

	struct iphdr *hdr = pktgen__push_iphdr(builder, length);

	if (!hdr)
		return NULL;

	hdr->version = 4;
	hdr->ihl = 5 + option_words;
	hdr->ttl = 64;
	/* No fragmentation by default */
	hdr->frag_off = 0;

	return hdr;
}

static __always_inline
__attribute__((warn_unused_result))
struct iphdr *pktgen__push_default_iphdr(struct pktgen *builder)
{
	return pktgen__push_default_iphdr_with_options(builder, 0);
}

static __always_inline
__attribute__((warn_unused_result))
struct ipv6_opt_hdr *pktgen__append_ipv6_extension_header(struct pktgen *builder,
							  __u8 nexthdr,
							  __u8 length)
{
	struct ipv6_opt_hdr *hdr = NULL;
	__u8 hdrlen = 0;

	/* TODO improve */
	switch (nexthdr) {
	case NEXTHDR_HOP:
		length = (0 + 1) << 3;
		hdr = pktgen__push_rawhdr(builder, length, PKT_LAYER_IPV6_HOP_BY_HOP);
		break;
	case NEXTHDR_AUTH:
		length = (2 + 2) << 2;
		hdr = pktgen__push_rawhdr(builder, length, PKT_LAYER_IPV6_AUTH);
		hdrlen = 2;
		break;
	case NEXTHDR_DEST:
		hdr = pktgen__push_rawhdr(builder, length, PKT_LAYER_IPV6_DEST);
		hdrlen = (length - 8) / 8;
		break;
	default:
		break;
	}

	if (!hdr)
		return NULL;

	hdr->hdrlen = hdrlen;

	return hdr;
}

static __always_inline
__attribute__((warn_unused_result))
struct ipv6hdr *pktgen__push_default_ipv6hdr(struct pktgen *builder)
{
	struct ipv6hdr *hdr = pktgen__push_rawhdr(builder,
			sizeof(struct ipv6hdr), PKT_LAYER_IPV6);

	if (!hdr)
		return NULL;

	memset(hdr, 0, sizeof(struct ipv6hdr));
	hdr->version = 6;
	hdr->hop_limit = IPV6_DEFAULT_HOPLIMIT;

	return hdr;
}

/* Push an empty ARP header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct arphdreth *pktgen__push_arphdr_ethernet(struct pktgen *builder)
{
	return pktgen__push_rawhdr(builder, sizeof(struct arphdreth), PKT_LAYER_ARP);
}

static __always_inline
__attribute__((warn_unused_result))
struct arphdreth *pktgen__push_default_arphdr_ethernet(struct pktgen *builder)
{
	struct arphdreth *arp = pktgen__push_arphdr_ethernet(builder);

	if (!arp)
		return NULL;

	arp->ar_hrd = bpf_htons(ARPHRD_ETHER);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4; /* Size of an IPv4 address */

	return arp;
}

/* Push an empty TCP header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct tcphdr *pktgen__push_tcphdr(struct pktgen *builder)
{
	return pktgen__push_rawhdr(builder, sizeof(struct tcphdr), PKT_LAYER_TCP);
}

/* Push a TCP header with sane defaults onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct tcphdr *pktgen__push_default_tcphdr(struct pktgen *builder)
{
	struct tcphdr *hdr = pktgen__push_tcphdr(builder);

	if (!hdr)
		return 0;

	hdr->syn = 1;
	hdr->seq = 123456;
	hdr->window = 65535;

	/* In most cases the doff is 5, so a good default if we can't
	 * calc the actual offset
	 */
	hdr->doff = 5;

	return hdr;
}

static __always_inline
__attribute__((warn_unused_result))
struct icmp6hdr *pktgen__push_icmp6hdr(struct pktgen *builder)
{
	return pktgen__push_rawhdr(builder, sizeof(struct icmp6hdr), PKT_LAYER_ICMPV6);
}

/* Push an empty ESP header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct ip_esp_hdr *pktgen__push_esphdr(struct pktgen *builder)
{
	return pktgen__push_rawhdr(builder, sizeof(struct ip_esp_hdr), PKT_LAYER_ESP);
}

/* Push a ESP header with sane defaults onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct ip_esp_hdr *pktgen__push_default_esphdr(struct pktgen *builder)
{
	struct ip_esp_hdr *hdr = pktgen__push_esphdr(builder);

	if (!hdr)
		return 0;

	hdr->spi = 1;
	hdr->seq_no = 10000;

	return hdr;
}

/* Push an empty SCTP header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct sctphdr *pktgen__push_sctphdr(struct pktgen *builder)
{
	return pktgen__push_rawhdr(builder, sizeof(struct sctphdr), PKT_LAYER_SCTP);
}

/* Push an empty UDP header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct udphdr *pktgen__push_udphdr(struct pktgen *builder)
{
	return pktgen__push_rawhdr(builder, sizeof(struct udphdr), PKT_LAYER_UDP);
}

static __always_inline
__attribute__((warn_unused_result))
struct udphdr *pktgen__push_default_udphdr(struct pktgen *builder)
{
	struct udphdr *hdr = pktgen__push_udphdr(builder);

	if (!hdr)
		return NULL;

	memset(hdr, 0, sizeof(*hdr));

	return hdr;
}

/* Push an empty VXLAN header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct vxlanhdr *pktgen__push_vxlanhdr(struct pktgen *builder)
{
	return pktgen__push_rawhdr(builder, sizeof(struct vxlanhdr), PKT_LAYER_VXLAN);
}

static __always_inline
__attribute__((warn_unused_result))
struct vxlanhdr *pktgen__push_default_vxlanhdr(struct pktgen *builder)
{
	struct vxlanhdr *hdr = pktgen__push_vxlanhdr(builder);

	if (!hdr)
		return NULL;

	memset(hdr, 0, sizeof(*hdr));

	hdr->vx_flags = bpf_htonl(1U << 27);

	return hdr;
}

/* Push an empty GENEVE header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct genevehdr *pktgen__push_genevehdr(struct pktgen *builder,
					 __u8 option_bytes)
{
	__u32 length = sizeof(struct genevehdr) + option_bytes;

	return pktgen__push_rawhdr(builder, length, PKT_LAYER_GENEVE);
}

static __always_inline
__attribute__((warn_unused_result))
struct genevehdr *pktgen__push_default_genevehdr_with_options(struct pktgen *builder,
							      __u8 option_bytes)
{
	struct genevehdr *hdr = pktgen__push_genevehdr(builder, option_bytes);

	if (!hdr)
		return NULL;

	memset(hdr, 0, sizeof(*hdr) + option_bytes);

	return hdr;
}

static __always_inline
__attribute__((warn_unused_result))
struct genevehdr *pktgen__push_default_genevehdr(struct pktgen *builder)
{
	struct genevehdr *hdr = pktgen__push_default_genevehdr_with_options(builder, 0);

	if (!hdr)
		return NULL;

	memset(hdr, 0, sizeof(*hdr));

	return hdr;
}

/* Push room for x bytes of data onto the packet */
static __always_inline
__attribute__((warn_unused_result))
void *pktgen__push_data_room(struct pktgen *builder, int len)
{
	struct __ctx_buff *ctx = builder->ctx;
	void *layer;
	int layer_idx;

	/* Request additional tailroom, and check that we got it. */
	ctx_adjust_troom(ctx, builder->cur_off + len - ctx_full_len(ctx));
	if (ctx_data(ctx) + builder->cur_off + len > ctx_data_end(ctx))
		return 0;

	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if ((__s64)builder->cur_off >= MAX_PACKET_OFF - len)
		return 0;

	layer = ctx_data(ctx) + builder->cur_off;
	layer_idx = pktgen__free_layer(builder);

	if (layer_idx < 0)
		return 0;

	builder->layers[layer_idx] = PKT_LAYER_DATA;
	builder->layer_offsets[layer_idx] = builder->cur_off;
	builder->cur_off += len;

	return layer;
}

/* Push data onto the packet */
static __always_inline
__attribute__((warn_unused_result))
void *pktgen__push_data(struct pktgen *builder, void *data, int len)
{
	void *pkt_data = pktgen__push_data_room(builder, len);

	if (!pkt_data)
		return 0;
	if (pkt_data + len > ctx_data_end(builder->ctx))
		return 0;

	memcpy(pkt_data, data, len);

	return pkt_data;
}

static __always_inline struct iphdr *
pktgen__push_ipv4_packet(struct pktgen *builder,
			 __u8 *smac, __u8 *dmac,
			 __be32 saddr, __be32 daddr)
{
	struct ethhdr *l2;
	struct iphdr *l3;

	l2 = pktgen__push_ethhdr(builder);
	if (!l2)
		return NULL;

	ethhdr__set_macs(l2, smac, dmac);

	l3 = pktgen__push_default_iphdr(builder);
	if (!l3)
		return NULL;

	l3->saddr = saddr;
	l3->daddr = daddr;

	return l3;
}

static __always_inline struct tcphdr *
pktgen__push_ipv4_tcp_packet(struct pktgen *builder,
			     __u8 *smac, __u8 *dmac,
			     __be32 saddr, __be32 daddr,
			     __be16 sport, __be16 dport)
{
	struct tcphdr *l4;
	struct iphdr *l3;

	l3 = pktgen__push_ipv4_packet(builder, smac, dmac, saddr, daddr);
	if (!l3)
		return NULL;

	l4 = pktgen__push_default_tcphdr(builder);
	if (!l4)
		return NULL;

	l4->source = sport;
	l4->dest = dport;

	return l4;
}

static __always_inline struct udphdr *
pktgen__push_ipv4_udp_packet(struct pktgen *builder,
			     __u8 *smac, __u8 *dmac,
			     __be32 saddr, __be32 daddr,
			     __be16 sport, __be16 dport)
{
	struct udphdr *l4;
	struct iphdr *l3;

	l3 = pktgen__push_ipv4_packet(builder, smac, dmac, saddr, daddr);
	if (!l3)
		return NULL;

	l4 = pktgen__push_default_udphdr(builder);
	if (!l4)
		return NULL;

	l4->source = sport;
	l4->dest = dport;

	return l4;
}

static __always_inline struct vxlanhdr *
pktgen__push_ipv4_vxlan_packet(struct pktgen *builder,
			       __u8 *smac, __u8 *dmac,
			       __be32 saddr, __be32 daddr,
			       __be16 sport, __be16 dport)
{
	struct udphdr *l4;

	l4 = pktgen__push_ipv4_udp_packet(builder, smac, dmac, saddr, daddr,
					  sport, dport);
	if (!l4)
		return NULL;

	return pktgen__push_default_vxlanhdr(builder);
}

static __always_inline struct tcphdr *
pktgen__push_ipv6_tcp_packet(struct pktgen *builder,
			     __u8 *smac, __u8 *dmac,
			     __u8 *saddr, __u8 *daddr,
			     __be16 sport, __be16 dport)
{
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	struct ethhdr *l2;

	l2 = pktgen__push_ethhdr(builder);
	if (!l2)
		return NULL;

	ethhdr__set_macs(l2, smac, dmac);

	l3 = pktgen__push_default_ipv6hdr(builder);
	if (!l3)
		return NULL;

	ipv6hdr__set_addrs(l3, saddr, daddr);

	l4 = pktgen__push_default_tcphdr(builder);
	if (!l4)
		return NULL;

	l4->source = sport;
	l4->dest = dport;

	return l4;
}

static __always_inline struct icmp6hdr *
pktgen__push_ipv6_icmp6_packet(struct pktgen *builder,
			       __u8 *smac, __u8 *dmac,
			       __u8 *saddr, __u8 *daddr,
			       __u8 icmp6_type)
{
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct icmp6hdr *l4;

	l2 = pktgen__push_ethhdr(builder);
	if (!l2)
		return NULL;

	ethhdr__set_macs(l2, smac, dmac);

	l3 = pktgen__push_default_ipv6hdr(builder);
	if (!l3)
		return NULL;

	ipv6hdr__set_addrs(l3, saddr, daddr);

	l4 = pktgen__push_icmp6hdr(builder);
	if (!l4)
		return NULL;

	l4->icmp6_type = icmp6_type;
	l4->icmp6_code = 0;
	l4->icmp6_cksum = 0;

	return l4;
}

static __always_inline void pktgen__finish_eth(const struct pktgen *builder, int i)
{
	struct ethhdr *eth_layer;
	__u64 layer_off;

	layer_off = builder->layer_offsets[i];
	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (layer_off >= MAX_PACKET_OFF - sizeof(struct ethhdr))
		return;

	eth_layer = ctx_data(builder->ctx) + layer_off;
	if ((void *)eth_layer + sizeof(struct ethhdr) > ctx_data_end(builder->ctx))
		return;

	if (i + 1 >= PKT_BUILDER_LAYERS)
		return;

	/* Set the proper next hdr value */
	switch (builder->layers[i + 1]) {
	case PKT_LAYER_IPV4:
		eth_layer->h_proto = __bpf_htons(ETH_P_IP);
		break;
	case PKT_LAYER_IPV6:
		eth_layer->h_proto = __bpf_htons(ETH_P_IPV6);
		break;
	case PKT_LAYER_ARP:
		eth_layer->h_proto = __bpf_htons(ETH_P_ARP);
		break;
	default:
		break;
	}
}

static __always_inline void pktgen__finish_ipv4(const struct pktgen *builder, int i)
{
	struct iphdr *ipv4_layer;
	__u64 layer_off;
	__u16 v4len;

	layer_off = builder->layer_offsets[i];
	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (layer_off >= MAX_PACKET_OFF - sizeof(struct iphdr))
		return;

	ipv4_layer = ctx_data(builder->ctx) + layer_off;
	if ((void *)ipv4_layer + sizeof(struct iphdr) > ctx_data_end(builder->ctx))
		return;

	if (i + 1 >= PKT_BUILDER_LAYERS)
		return;

	switch (builder->layers[i + 1]) {
	case PKT_LAYER_TCP:
		ipv4_layer->protocol = IPPROTO_TCP;
		break;
	case PKT_LAYER_UDP:
		ipv4_layer->protocol = IPPROTO_UDP;
		break;
	case PKT_LAYER_ICMP:
		ipv4_layer->protocol = IPPROTO_ICMP;
		break;
	case PKT_LAYER_SCTP:
		ipv4_layer->protocol = IPPROTO_SCTP;
		break;
	case PKT_LAYER_ESP:
		ipv4_layer->protocol = IPPROTO_ESP;
		break;
	default:
		break;
	}

	v4len = (__be16)(builder->cur_off - builder->layer_offsets[i]);
	/* Calculate total length, which is IPv4 hdr + all layers after it */
	ipv4_layer->tot_len = __bpf_htons(v4len);
	ipv4_layer->check = csum_fold(csum_diff(NULL, 0, ipv4_layer, sizeof(struct iphdr), 0));
}

static __always_inline void pktgen__finish_ipv6(const struct pktgen *builder, int i)
{
	struct ipv6hdr *ipv6_layer;
	__u64 layer_off;
	__u16 v6len;

	layer_off = builder->layer_offsets[i];
	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (layer_off >= MAX_PACKET_OFF - sizeof(struct ipv6hdr))
		return;

	ipv6_layer = ctx_data(builder->ctx) + builder->layer_offsets[i];
	if ((void *)ipv6_layer + sizeof(struct ipv6hdr) >
		ctx_data_end(builder->ctx))
		return;

	if (i + 1 >= PKT_BUILDER_LAYERS)
		return;

	switch (builder->layers[i + 1]) {
	case PKT_LAYER_IPV6_HOP_BY_HOP:
		ipv6_layer->nexthdr = NEXTHDR_HOP;
		break;
	case PKT_LAYER_IPV6_AUTH:
		ipv6_layer->nexthdr = NEXTHDR_AUTH;
		break;
	case PKT_LAYER_IPV6_DEST:
		ipv6_layer->nexthdr = NEXTHDR_DEST;
		break;
	case PKT_LAYER_TCP:
		ipv6_layer->nexthdr = IPPROTO_TCP;
		break;
	case PKT_LAYER_UDP:
		ipv6_layer->nexthdr = IPPROTO_UDP;
		break;
	case PKT_LAYER_ICMPV6:
		ipv6_layer->nexthdr = IPPROTO_ICMPV6;
		break;
	case PKT_LAYER_SCTP:
		ipv6_layer->nexthdr = IPPROTO_SCTP;
		break;
	case PKT_LAYER_ESP:
		ipv6_layer->nexthdr = IPPROTO_ESP;
		break;
	default:
		break;
	}

	v6len = (__be16)(builder->cur_off + sizeof(struct ipv6hdr) -
		builder->layer_offsets[i]);

	/* Calculate payload length, which doesn't include the header size */
	ipv6_layer->payload_len = __bpf_htons(v6len);
}

static __always_inline void pktgen__finish_ipv6_opt(const struct pktgen *builder, int i)
{
	struct ipv6_opt_hdr *ipv6_opt_layer;
	__u64 layer_off;

	layer_off = builder->layer_offsets[i];
	if (layer_off >= MAX_PACKET_OFF - sizeof(struct ipv6_opt_hdr))
		return;

	ipv6_opt_layer = ctx_data(builder->ctx) + layer_off;
	if ((void *)(ipv6_opt_layer + 1) > ctx_data_end(builder->ctx))
		return;

	if (i + 1 >= PKT_BUILDER_LAYERS)
		return;

	switch (builder->layers[i + 1]) {
	case PKT_LAYER_IPV6_HOP_BY_HOP:
		ipv6_opt_layer->nexthdr = NEXTHDR_HOP;
		break;
	case PKT_LAYER_IPV6_AUTH:
		ipv6_opt_layer->nexthdr = NEXTHDR_AUTH;
		break;
	case PKT_LAYER_IPV6_DEST:
		ipv6_opt_layer->nexthdr = NEXTHDR_DEST;
		break;
	case PKT_LAYER_TCP:
		ipv6_opt_layer->nexthdr = IPPROTO_TCP;
		break;
	case PKT_LAYER_UDP:
		ipv6_opt_layer->nexthdr = IPPROTO_UDP;
		break;
	case PKT_LAYER_ICMPV6:
		ipv6_opt_layer->nexthdr = IPPROTO_ICMPV6;
		break;
	case PKT_LAYER_SCTP:
		ipv6_opt_layer->nexthdr = IPPROTO_SCTP;
		break;
	default:
		break;
	}
}

static __always_inline void pktgen__finish_tcp(const struct pktgen *builder, int i)
{
	struct tcphdr *tcp_layer;
	__u64 layer_off;
	__u64 hdr_size;

	layer_off = builder->layer_offsets[i];
	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (layer_off >= MAX_PACKET_OFF - sizeof(struct tcphdr))
		return;

	tcp_layer = ctx_data(builder->ctx) + layer_off;
	if ((void *)tcp_layer + sizeof(struct tcphdr) >
		ctx_data_end(builder->ctx))
		return;

	if (i + 1 >= PKT_BUILDER_LAYERS)
		return;

	/* Calculate the data offset, this is the diff between start of header
	 * and start of data in 32-bit words (bytes divided by 4).
	 */

	if (builder->layers[i + 1] == PKT_LAYER_NONE) {
		/* If no data or next header exists, calc using the current offset */
		hdr_size = builder->cur_off - builder->layer_offsets[i];
	} else {
		hdr_size = builder->layer_offsets[i + 1] -
				builder->layer_offsets[i];
	}

	tcp_layer->doff = (__u16)hdr_size / 4;
	tcp_layer->check = 0;
	tcp_layer->check = csum_fold(csum_diff(NULL, 0, tcp_layer, sizeof(struct tcphdr), 0));
}

static __always_inline void pktgen__finish_udp(const struct pktgen *builder, int i)
{
	struct iphdr *ipv4_layer;
	__u64 ipv4_offset;
	struct udphdr *udp_layer;
	__u64 layer_off;
	__u16 len;

	layer_off = builder->layer_offsets[i];
	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (layer_off >= MAX_PACKET_OFF - sizeof(struct udphdr))
		return;

	udp_layer = ctx_data(builder->ctx) + layer_off;
	if ((void *)udp_layer + sizeof(struct udphdr) >
		ctx_data_end(builder->ctx))
		return;

	udp_layer->check = 0;
	len = (__be16)(builder->cur_off - builder->layer_offsets[i]);
	udp_layer->len = __bpf_htons(len);

	if (i - 1 >= 0 && builder->layers[i - 1] == PKT_LAYER_IPV4) 
	{
		ipv4_offset =  builder->layer_offsets[i-1];
		if (ipv4_offset >= MAX_PACKET_OFF - sizeof(struct iphdr))
			return;
		
		ipv4_layer = ctx_data(builder->ctx) + ipv4_offset;
		if ((void *)ipv4_layer + sizeof(struct iphdr) > ctx_data_end(builder->ctx))
			return;

		udp_layer->check = 0;
		udp_layer->check = csum_udp(ipv4_layer, udp_layer, ctx_data_end(builder->ctx));
	}
}

static __always_inline void pktgen__finish_icmp(const struct pktgen *builder, int i)
{
	struct icmphdr *icmp_layer;
	__u64 layer_off;

	layer_off = builder->layer_offsets[i];
	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (layer_off >= MAX_PACKET_OFF - sizeof(struct icmphdr))
		return;

	icmp_layer = ctx_data(builder->ctx) + layer_off;
	if ((void *)icmp_layer + sizeof(struct icmphdr) >
		ctx_data_end(builder->ctx))
		return;

	icmp_layer->checksum = 0;
	icmp_layer->checksum = csum_fold(csum_diff(NULL, 0, icmp_layer, sizeof(struct icmphdr), 0));
}

static __always_inline void pktgen__finish_icmpv6(const struct pktgen *builder, int i)
{
	struct icmp6hdr *icmpv6_layer;
	__u64 layer_off;

	layer_off = builder->layer_offsets[i];
	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (layer_off >= MAX_PACKET_OFF - sizeof(struct icmp6hdr))
		return;

	icmpv6_layer = ctx_data(builder->ctx) + layer_off;
	if ((void *)icmpv6_layer + sizeof(struct icmp6hdr) >
		ctx_data_end(builder->ctx))
		return;

	icmpv6_layer->icmp6_cksum = 0;
	icmpv6_layer->icmp6_cksum = csum_fold(csum_diff(NULL, 0, icmpv6_layer, sizeof(struct icmp6hdr), 0));
}

static __always_inline void pktgen__finish_geneve(const struct pktgen *builder, int i)
{
	struct genevehdr *geneve_layer;
	__u64 layer_off;

	layer_off = builder->layer_offsets[i];
	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (layer_off >= MAX_PACKET_OFF - sizeof(struct genevehdr))
		return;

	geneve_layer = ctx_data(builder->ctx) + layer_off;
	if ((void *)geneve_layer + sizeof(struct genevehdr) >
		ctx_data_end(builder->ctx))
		return;

	if (i + 1 >= PKT_BUILDER_LAYERS)
		return;

	switch (builder->layers[i + 1]) {
	case PKT_LAYER_ETH:
		geneve_layer->protocol_type = __bpf_htons(ETH_P_TEB);
		break;
	default:
		break;
	}
}

/* Do a finishing pass on all the layers, which will set correct next layer
 * fields and length values. TODO checksum calculation?
 */
static __always_inline
void pktgen__finish(const struct pktgen *builder)
{
	#pragma unroll
	for (int i = 0; i < PKT_BUILDER_LAYERS; i++) {
		switch (builder->layers[i]) {
		case PKT_LAYER_NONE:
			/* A none signals the end of the layer stack */
			return;

		case PKT_LAYER_ETH:
			pktgen__finish_eth(builder, i);
			break;

		case PKT_LAYER_8021Q:
			/* TODO set next protocol once 802.1Q is added */
			break;

		case PKT_LAYER_IPV4:
			pktgen__finish_ipv4(builder, i);
			break;

		case PKT_LAYER_IPV6:
			pktgen__finish_ipv6(builder, i);
			break;

		case PKT_LAYER_IPV6_HOP_BY_HOP:
		case PKT_LAYER_IPV6_AUTH:
		case PKT_LAYER_IPV6_DEST:
			pktgen__finish_ipv6_opt(builder, i);
			break;

		case PKT_LAYER_TCP:
			pktgen__finish_tcp(builder, i);
			break;

		case PKT_LAYER_ESP:
			/* No sizes or checksums for ESP, so nothing to do */
			break;

		case PKT_LAYER_ARP:
			/* No sizes or checksums for ARP, so nothing to do */
			break;

		case PKT_LAYER_UDP:
			pktgen__finish_udp(builder, i);
			break;

		case PKT_LAYER_ICMP:
			pktgen__finish_icmp(builder, i);
			break;

		case PKT_LAYER_ICMPV6:
			pktgen__finish_icmpv6(builder, i);
			break;

		case PKT_LAYER_SCTP:
			/* TODO implement checksum calc */
			break;

		case PKT_LAYER_GENEVE:
			pktgen__finish_geneve(builder, i);
			break;

		case PKT_LAYER_VXLAN:
			break;

		case PKT_LAYER_DATA:
			/* User defined data, nothing to do */
			break;
		}
	}
};
