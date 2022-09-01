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
 *  without having to come up with custom addresses.
 */

#define mac_one   {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xEF}
#define mac_two   {0x13, 0x37, 0x13, 0x37, 0x13, 0x37}
#define mac_three {0x31, 0x41, 0x59, 0x26, 0x35, 0x89}
#define mac_four  {0x0D, 0x1D, 0x22, 0x59, 0xA9, 0xC2}
#define mac_five  {0x15, 0x21, 0x39, 0x45, 0x4D, 0x5D}
#define mac_six   {0x08, 0x14, 0x1C, 0x32, 0x52, 0x7E}

/* A collection of pre-defined IP addresses, so tests can reuse them without
 *  having to come up with custom ips.
 */

#define IPV4(a, b, c, d) (((d) << 24) + ((c) << 16) + ((b) << 8) + (a))

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

/* Source port to be used by a client */
#define tcp_src_one	__bpf_htons(22334)
#define tcp_src_two	__bpf_htons(33445)
#define tcp_src_three	__bpf_htons(44556)

#define tcp_svc_one	__bpf_htons(80)
#define tcp_svc_two	__bpf_htons(443)
#define tcp_svc_three	__bpf_htons(53)

#define default_data "Should not change!!"

enum pkt_layer {
	PKT_LAYER_NONE,

	/* L2 layers */
	PKT_LAYER_ETH,
	PKT_LAYER_8021Q,

	/* L3 layers */
	PKT_LAYER_IPV4,
	PKT_LAYER_IPV6,
	PKT_LAYER_ARP,
	/* TODO IPv6 extension headers */

	/* L4 layers */
	PKT_LAYER_TCP,
	PKT_LAYER_UDP,
	PKT_LAYER_ICMP,
	PKT_LAYER_ICMPV6,

	/* Packet data*/
	PKT_LAYER_DATA,
};

#define PKT_BUILDER_LAYERS 6

#define MAX_PACKET_OFF 0xffff

/* Packet builder */
struct pktgen {
	struct __ctx_buff *ctx;
	__u16 cur_off;
	__u16 layer_offsets[PKT_BUILDER_LAYERS];
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

	/* Request additional tailroom, and check that we got it. */
	ctx_adjust_troom(ctx, builder->cur_off + sizeof(struct ethhdr) - ctx_full_len(ctx));
	if (ctx_data(ctx) + builder->cur_off + sizeof(struct ethhdr) > ctx_data_end(ctx))
		return 0;

	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (builder->cur_off >= MAX_PACKET_OFF - sizeof(struct ethhdr))
		return 0;

	layer = ctx_data(ctx) + builder->cur_off;
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
struct iphdr *pktgen__push_iphdr(struct pktgen *builder)
{
	struct __ctx_buff *ctx = builder->ctx;
	struct iphdr *layer;
	int layer_idx;

	/* Request additional tailroom, and check that we got it. */
	ctx_adjust_troom(ctx, builder->cur_off + sizeof(struct iphdr) - ctx_full_len(ctx));
	if (ctx_data(ctx) + builder->cur_off + sizeof(struct iphdr) > ctx_data_end(ctx))
		return 0;

	/* Check that any value within the struct will not exceed a u16 which
	 * is the max allowed offset within a packet from ctx->data.
	 */
	if (builder->cur_off >= MAX_PACKET_OFF - sizeof(struct iphdr))
		return 0;

	layer = ctx_data(ctx) + builder->cur_off;
	layer_idx = pktgen__free_layer(builder);

	if (layer_idx < 0)
		return 0;

	builder->layers[layer_idx] = PKT_LAYER_IPV4;
	builder->layer_offsets[layer_idx] = builder->cur_off;
	builder->cur_off += sizeof(struct iphdr);

	return layer;
}

/* Push a IPv4 header with sane defaults onto the packet */
static __always_inline
__attribute__((warn_unused_result))
struct iphdr *pktgen__push_default_iphdr(struct pktgen *builder)
{
	struct iphdr *hdr = pktgen__push_iphdr(builder);

	if (!hdr)
		return 0;

	hdr->version = 4;
	/* No options by default */
	hdr->ihl = 5;
	hdr->ttl = 64;
	/* No fragmentation by default */
	hdr->frag_off = 0;

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
	if (builder->cur_off >= MAX_PACKET_OFF - len)
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
	struct tcphdr *tcp_layer;
	__u16 layer_off;
	__u16 v4len;
	__be16 v6len;
	__u16 hdr_size;

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
			case PKT_LAYER_TCP:
				ipv6_layer->nexthdr = IPPROTO_TCP;
				break;
			case PKT_LAYER_UDP:
				ipv6_layer->nexthdr = IPPROTO_UDP;
				break;
			case PKT_LAYER_ICMPV6:
				ipv6_layer->nexthdr = IPPROTO_ICMPV6;
				break;
			default:
				break;
			}

			v6len = (__be16)(builder->cur_off + sizeof(struct ipv6hdr) -
				builder->layer_offsets[i]);

			/* Calculate payload length, which doesn't include the header size */
			ipv6_layer->payload_len = __bpf_htons(v6len);

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

			tcp_layer->doff = hdr_size / 4;

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

		case PKT_LAYER_DATA:
			/* User defined data, nothing to do */
			break;
		}
	}
exit:
	return;
};

#endif /* __TEST_PKTGEN__ */
