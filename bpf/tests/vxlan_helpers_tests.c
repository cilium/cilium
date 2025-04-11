// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include "bpf/ctx/skb.h"
#include "pktgen.h"

#define TUNNEL_PROTOCOL TUNNEL_PROTOCOL_VXLAN
#define TUNNEL_PORT 8472
#define TUNNEL_PORT_BAD 0
#define VXLAN_VNI 0xDEADBE
#define VXLAN_VNI_NEW 0xCAFEBE
#define UDP_CHECK 0xDEAD

#include "node_config.h"
#include "lib/common.h"
#include "lib/vxlan.h"

#include <lib/ipv4.h>
#include <lib/ipv6.h>

/* this had to be used instead of the pktgen__push methods since these methods
 * use layer accounting and will fail when pushing an ipv4 header past its
 * assumed layer
 */
static __always_inline void
mk_data(const __u8 *buff) {
	struct ethhdr *eth = (struct ethhdr *)buff;

	memcpy(&eth->h_source, (__u8 *)mac_one, sizeof(mac_three));
	memcpy(&eth->h_dest, (__u8 *)mac_one, sizeof(mac_four));
	eth->h_proto = ETH_P_IP;

	struct iphdr *ipv4 = (struct iphdr *)(buff + sizeof(struct ethhdr));

	ipv4->saddr = v4_pod_one;
	ipv4->daddr = v4_pod_two;
}

/* this had to be used instead of the pktgen__push methods since these methods
 * use layer accounting and will fail when pushing an ipv header past its
 * assumed layer
 */
static __always_inline void
mk_data_v6(const __u8 *buff) {
	struct ethhdr *eth = (struct ethhdr *)buff;

	memcpy(&eth->h_source, (__u8 *)mac_one, sizeof(mac_three));
	memcpy(&eth->h_dest, (__u8 *)mac_one, sizeof(mac_four));
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	struct ipv6hdr *ipv6 = (struct ipv6hdr *)(buff + sizeof(struct ethhdr));

	ipv6->nexthdr = 6;
	memcpy((__u8 *)&ipv6->saddr, (__u8 *)v6_pod_one, 16);
	memcpy((__u8 *)&ipv6->daddr, (__u8 *)v6_pod_two, 16);
}

static __always_inline int
mk_packet(struct __ctx_buff *ctx, bool v6) {
	struct pktgen builder;
	struct udphdr *l4;
	struct vxlanhdr *vx;
	/* data is encap'd ipv4 packet, we don't care about l4 */
	__u8 encap_data[sizeof(struct ethhdr) + sizeof(struct ipv6hdr)];
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one,
					  (__u8 *)mac_two,
					  v4_node_one,
					  v4_node_two,
					  666,
					  bpf_htons(TUNNEL_PORT));
	if (!l4)
		return TEST_ERROR;

	l4->check = UDP_CHECK;

	vx = pktgen__push_default_vxlanhdr(&builder);
	if (!vx)
		return TEST_ERROR;

	vx->vx_vni = bpf_htonl(VXLAN_VNI << 8);

	if (v6){
		mk_data_v6(encap_data);
		data = pktgen__push_data(&builder, encap_data, sizeof(encap_data));
	}
	else {
		mk_data(encap_data);
		/* truncate down to v4 buffer size */
		data = pktgen__push_data(&builder,
				         encap_data,
					 sizeof(encap_data) -
					 (sizeof(struct ipv6hdr) -
					 sizeof(struct iphdr)));
	}

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "vxlan_get_vni_success")
static __always_inline int
pktgen_vxlan_mock_check3(struct __ctx_buff *ctx) {
	return mk_packet(ctx, false);
}

CHECK("tc", "vxlan_get_vni_success")
int check3(struct __ctx_buff *ctx)
{
	test_init();

	void *data, *data_end = NULL;
	struct iphdr *ipv4 = NULL;

	assert(revalidate_data(ctx, &data, &data_end, &ipv4));
	assert(vxlan_get_vni(data, data_end, ETH_HLEN + ipv4_hdrlen(ipv4)) == VXLAN_VNI);

	test_finish();
}

PKTGEN("tc", "vxlan_get_inner_ipv4_success")
static __always_inline int
pktgen_vxlan_mock_check4(struct __ctx_buff *ctx) {
	return mk_packet(ctx, false);
}

CHECK("tc", "vxlan_get_inner_ipv4_success")
int check4(struct __ctx_buff *ctx)
{
	test_init();

	void *data, *data_end = NULL;
	struct iphdr *ipv4 = NULL;
	struct iphdr *inner_ipv4 = NULL;

	assert(revalidate_data(ctx, &data, &data_end, &ipv4));
	assert(vxlan_get_inner_ipv4(data, data_end, ETH_HLEN + ipv4_hdrlen(ipv4), &inner_ipv4));

	assert(inner_ipv4->saddr == v4_pod_one);
	assert(inner_ipv4->daddr == v4_pod_two);

	test_finish();
}

PKTGEN("tc", "vxlan_rewrite_vni_success")
static __always_inline int
pktgen_vxlan_mock_check5(struct __ctx_buff *ctx) {
	return mk_packet(ctx, false);
}

CHECK("tc", "vxlan_rewrite_vni_success")
int check5(struct __ctx_buff *ctx)
{
	test_init();

	void *data, *data_end = NULL;
	struct iphdr *ipv4 = NULL;
	struct udphdr *udp = NULL;
	__u32 vni = 0;
	__u32 l4_off;

	assert(revalidate_data(ctx, &data, &data_end, &ipv4));

	l4_off = ETH_HLEN + ipv4_hdrlen(ipv4);

	assert(vxlan_rewrite_vni(ctx, data, data_end, l4_off, VXLAN_VNI_NEW));

	/* packet data was touched so revalidate */
	assert(revalidate_data(ctx, &data, &data_end, &ipv4));

	vni = vxlan_get_vni(data, data_end, l4_off);
	assert(vni == VXLAN_VNI_NEW);

	if (data + l4_off + sizeof(struct udphdr) > data_end)
		test_fatal("udp out of bounds");

	/* assert udp checksum was updated */
	udp = (struct udphdr *)(data + l4_off);
	assert(udp->check != UDP_CHECK);

	test_finish();
}

PKTGEN("tc", "vxlan_get_inner_ipv6_success")
static __always_inline int
pktgen_vxlan_mock_check1(struct __ctx_buff *ctx) {
	return mk_packet(ctx, true);
}

CHECK("tc", "vxlan_get_inner_ipv6_success")
int check1(struct __ctx_buff *ctx)
{
	test_init();

	void *data, *data_end = NULL;
	struct iphdr *ipv4 = NULL;
	struct ipv6hdr *inner_ipv6 = NULL;
	union v6addr *v6s, *v6d = NULL;

	assert(revalidate_data(ctx, &data, &data_end, &ipv4));
	assert(vxlan_get_inner_ipv6(data, data_end, ETH_HLEN + ipv4_hdrlen(ipv4), &inner_ipv6));

	v6s = (union v6addr *)&inner_ipv6->saddr;
	assert(bpf_ntohl(v6s->p1) == 0xfd040000);
	assert(bpf_ntohl(v6s->p2) == 0x00000000);
	assert(bpf_ntohl(v6s->p3) == 0x00000000);
	assert(bpf_ntohl(v6s->p4) == 0x00000001);

	v6d = (union v6addr *)&inner_ipv6->daddr;
	assert(bpf_ntohl(v6d->p1) == 0xfd040000);
	assert(bpf_ntohl(v6d->p2) == 0x00000000);
	assert(bpf_ntohl(v6d->p3) == 0x00000000);
	assert(bpf_ntohl(v6d->p4) == 0x00000002);

	test_finish();
}

PKTGEN("tc", "vxlan_get_inner_proto")
static __always_inline int
pktgen_vxlan_mock_check2(struct __ctx_buff *ctx) {
	return mk_packet(ctx, true);
}

CHECK("tc", "vxlan_get_inner_proto")
int check2(struct __ctx_buff *ctx)
{
	test_init();

	void *data, *data_end = NULL;
	struct iphdr *ipv4 = NULL;
	__be16 inner_l3_proto = 0;
	__u32 l4_off;

	assert(revalidate_data(ctx, &data, &data_end, &ipv4));

	l4_off = ETH_HLEN + ipv4_hdrlen(ipv4);
	inner_l3_proto = vxlan_get_inner_proto(data, data_end, l4_off);
	assert(inner_l3_proto == bpf_htons(ETH_P_IPV6));

	test_finish();
}
