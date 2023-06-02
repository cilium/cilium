/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __TEST_PKTGEN__
#define __TEST_PKTGEN__

#include <bpf/compiler.h>
#include <bpf/builtins.h>
#include <bpf/helpers.h>

#include <lib/endian.h>

#include <linux/byteorder.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>

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

/* IPv6 addresses for pods in the cluster */
static volatile const __u8 v6_pod_one[] = {0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 1};
static volatile const __u8 v6_pod_two[] = {0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 2};
static volatile const __u8 v6_pod_three[] = {0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 3};

/* IPv6 addresses for nodes in the cluster */
static volatile const __u8 v6_node_one[] = {0xfd, 0x05, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 1};
static volatile const __u8 v6_node_two[] = {0xfd, 0x06, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 2};
static volatile const __u8 v6_node_three[] = {0xfd, 0x07, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 3};

/* Source port to be used by a client */
#define tcp_src_one	__bpf_htons(22334)
#define tcp_src_two	__bpf_htons(33445)
#define tcp_src_three	__bpf_htons(44556)

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

	/* Packet data*/
	PKT_LAYER_DATA,
};

#define IPV6_DEFAULT_HOPLIMIT 64

#define PKT_BUILDER_LAYERS 6

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

/* Push an empty ethernet header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct ethhdr *pktgen__push_ethhdr(struct pktgen *builder)
{
	struct __ctx_buff *ctx = builder->ctx;
	struct ethhdr *layer;
	int layer_idx;
	void *data;

	/* Request additional tailroom, and check that we got it. */
	ctx_adjust_troom(ctx, builder->cur_off + sizeof(struct ethhdr) - ctx_full_len(ctx));
	data = ctx_data(ctx);
	if (data + builder->cur_off + sizeof(struct ethhdr) > ctx_data_end(ctx))
		return 0;

	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (builder->cur_off >= MAX_PACKET_OFF - sizeof(struct ethhdr))
		return 0;

	layer = data + builder->cur_off;
	layer_idx = pktgen__free_layer(builder);

	if (layer_idx < 0)
		return 0;

	builder->layers[layer_idx] = PKT_LAYER_ETH;
	builder->layer_offsets[layer_idx] = builder->cur_off;
	builder->cur_off += sizeof(struct ethhdr);

	return layer;
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
	struct __ctx_buff *ctx = builder->ctx;
	void *data, *data_end;
	struct iphdr *layer;
	int layer_idx;

	if (option_bytes > MAX_IPOPTLEN)
		return 0;

	/* Request additional tailroom, and check that we got it. */
	ctx_adjust_troom(ctx, builder->cur_off + length - ctx_full_len(ctx));
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + builder->cur_off + length > data_end)
		return 0;

	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (builder->cur_off >= MAX_PACKET_OFF - length)
		return 0;

	layer = data + builder->cur_off;
	layer_idx = pktgen__free_layer(builder);

	if (layer_idx < 0)
		return 0;

	builder->layers[layer_idx] = PKT_LAYER_IPV4;
	builder->layer_offsets[layer_idx] = builder->cur_off;
	builder->cur_off += length;

	return layer;
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
	struct __ctx_buff *ctx = builder->ctx;
	struct ipv6hdr *layer;
	int layer_idx;

	/* Request additional tailroom, and check that we got it. */
	ctx_adjust_troom(ctx, builder->cur_off + sizeof(struct ipv6hdr) - ctx_full_len(ctx));
	if (ctx_data(ctx) + builder->cur_off + sizeof(struct ipv6hdr) > ctx_data_end(ctx))
		return 0;

	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (builder->cur_off >= MAX_PACKET_OFF - sizeof(struct ipv6hdr))
		return 0;

	layer = ctx_data(ctx) + builder->cur_off;
	layer_idx = pktgen__free_layer(builder);

	if (layer_idx < 0)
		return 0;

	builder->layers[layer_idx] = PKT_LAYER_IPV6;
	builder->layer_offsets[layer_idx] = builder->cur_off;
	builder->cur_off += sizeof(struct ipv6hdr);

	return layer;
}

/* Push a IPv4 header with sane defaults and options onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct iphdr *pktgen__push_default_iphdr_with_options(struct pktgen *builder,
						      __u8 option_words)
{
	struct iphdr *hdr = pktgen__push_iphdr(builder, option_words * 4);

	if (!hdr)
		return 0;

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
void *pktgen__push_rawhdr(struct pktgen *builder, __u16 hdrsize, enum pkt_layer type)
{
	struct __ctx_buff *ctx = builder->ctx;
	void *layer = NULL;
	int layer_idx;

	ctx_adjust_troom(ctx, builder->cur_off + hdrsize - ctx_full_len(ctx));
	if (ctx_data(ctx) + builder->cur_off + hdrsize > ctx_data_end(ctx))
		return NULL;

	if (builder->cur_off >= MAX_PACKET_OFF - hdrsize)
		return NULL;

	layer = ctx_data(ctx) + builder->cur_off;
	layer_idx = pktgen__free_layer(builder);

	if (layer_idx < 0)
		return NULL;

	builder->layers[layer_idx] = type;
	builder->layer_offsets[layer_idx] = builder->cur_off;
	builder->cur_off += hdrsize;

	return layer;
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

	if ((void *)hdr + length > ctx_data_end(builder->ctx))
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

	if ((void *) hdr + sizeof(struct ipv6hdr) > ctx_data_end(builder->ctx))
		return NULL;

	memset(hdr, 0, sizeof(struct ipv6hdr));
	hdr->version = 6;
	hdr->hop_limit = IPV6_DEFAULT_HOPLIMIT;

	return hdr;
}

/* Push an empty TCP header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct tcphdr *pktgen__push_tcphdr(struct pktgen *builder)
{
	struct __ctx_buff *ctx = builder->ctx;
	struct tcphdr *layer;
	int layer_idx;

	/* Request additional tailroom, and check that we got it. */
	ctx_adjust_troom(ctx, builder->cur_off + sizeof(struct tcphdr) - ctx_full_len(ctx));
	if (ctx_data(ctx) + builder->cur_off + sizeof(struct tcphdr) > ctx_data_end(ctx))
		return 0;

	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (builder->cur_off >= MAX_PACKET_OFF - sizeof(struct tcphdr))
		return 0;

	layer = ctx_data(ctx) + builder->cur_off;
	layer_idx = pktgen__free_layer(builder);

	if (layer_idx < 0)
		return 0;

	builder->layers[layer_idx] = PKT_LAYER_TCP;
	builder->layer_offsets[layer_idx] = builder->cur_off;
	builder->cur_off += sizeof(struct tcphdr);

	return layer;
}

/* Push a TCP header with sane defaults onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct tcphdr *pktgen__push_default_tcphdr(struct pktgen *builder)
{
	struct tcphdr *hdr = pktgen__push_tcphdr(builder);

	if (!hdr)
		return 0;
	if ((void *)hdr + sizeof(struct tcphdr) > ctx_data_end(builder->ctx))
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

/* Push an empty SCTP header onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct sctphdr *pktgen__push_sctphdr(struct pktgen *builder)
{
	struct __ctx_buff *ctx = builder->ctx;
	struct sctphdr *layer;
	int layer_idx;

	/* Request additional tailroom, and check that we got it. */
	ctx_adjust_troom(ctx, builder->cur_off + sizeof(struct sctphdr) - ctx_full_len(ctx));
	if (ctx_data(ctx) + builder->cur_off + sizeof(struct sctphdr) > ctx_data_end(ctx))
		return 0;

	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (builder->cur_off >= MAX_PACKET_OFF - sizeof(struct sctphdr))
		return 0;

	layer = ctx_data(ctx) + builder->cur_off;
	layer_idx = pktgen__free_layer(builder);

	if (layer_idx < 0)
		return 0;

	builder->layers[layer_idx] = PKT_LAYER_SCTP;
	builder->layer_offsets[layer_idx] = builder->cur_off;
	builder->cur_off += sizeof(struct sctphdr);

	return layer;
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

/* Do a finishing pass on all the layers, which will set correct next layer
 * fields and length values. TODO checksum calculation?
 */
static __always_inline
void pktgen__finish(const struct pktgen *builder)
{
	struct ethhdr *eth_layer;
	struct iphdr *ipv4_layer;
	struct ipv6hdr *ipv6_layer;
	struct ipv6_opt_hdr *ipv6_opt_layer;
	struct tcphdr *tcp_layer;
	__u64 layer_off;
	__u16 v4len;
	__be16 v6len;
	__u64 hdr_size;

	#pragma unroll
	for (int i = 0; i < PKT_BUILDER_LAYERS; i++) {
		switch (builder->layers[i]) {
		case PKT_LAYER_NONE:
			/* A none signals the end of the layer stack */
			goto exit;

		case PKT_LAYER_ETH:
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

			break;

		case PKT_LAYER_8021Q:
			/* TODO set next protocol once 802.1Q is added */
			break;

		case PKT_LAYER_IPV4:
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
			default:
				break;
			}

			v4len = (__be16)(builder->cur_off - builder->layer_offsets[i]);
			/* Calculate total length, which is IPv4 hdr + all layers after it */
			ipv4_layer->tot_len = __bpf_htons(v4len);

			break;

		case PKT_LAYER_IPV6:
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
			default:
				break;
			}

			v6len = (__be16)(builder->cur_off + sizeof(struct ipv6hdr) -
				builder->layer_offsets[i]);

			/* Calculate payload length, which doesn't include the header size */
			ipv6_layer->payload_len = __bpf_htons(v6len);

			break;

		case PKT_LAYER_IPV6_HOP_BY_HOP:
		case PKT_LAYER_IPV6_AUTH:
		case PKT_LAYER_IPV6_DEST:
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

			break;

		case PKT_LAYER_TCP:
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

			break;

		case PKT_LAYER_ARP:
			/* No sizes or checksums for ARP, so nothing to do */
			break;

		case PKT_LAYER_UDP:
			/* No sizes or checksums for UDP, so nothing to do */
			break;

		case PKT_LAYER_ICMP:
			/* TODO implement checksum calc? */
			break;

		case PKT_LAYER_ICMPV6:
			/* TODO implement checksum calc? */
			break;

		case PKT_LAYER_SCTP:
			/* TODO implement checksum calc */
			break;

		case PKT_LAYER_DATA:
			/* User defined data, nothing to do */
			break;
		}
	}
exit:
	return;
};

#endif /* __TEST_PKTGEN__ */
