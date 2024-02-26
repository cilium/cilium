/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_VXLAN_H_
#define __LIB_VXLAN_H_

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include "lib/csum.h"

/*
 * Returns true if the skb associated with data pointers is a vxlan encapsulated
 * packet.
 *
 * The determination is made by comparing the UDP destination port with
 * the tunnel_port provided to the function.
 */
static __always_inline bool
vxlan_skb_is_vxlan_v4(const void *data, const void *data_end,
		      const struct iphdr *ipv4, const __u16 tunnel_port)
{
	struct udphdr *udp = NULL;
	__u32 l3_size = 0;

	if (ipv4->protocol != IPPROTO_UDP)
		return false;

	l3_size = ipv4->ihl * 4;

	if (data + sizeof(struct ethhdr) + l3_size + sizeof(struct udphdr)
	    + sizeof(struct vxlanhdr) > data_end)
		return false;

	udp = (struct udphdr *)(data + sizeof(struct ethhdr) + l3_size);

	if (udp->dest == bpf_htons(tunnel_port))
		return true;

	return false;
}

/*
 * Returns the VNI in the native host's endian format of a xvlan encap'd packet.
 *
 * The caller must ensure the skb associated with these data buffers are infact
 * a vxlan encapsulated packet before invoking this function.
 *
 * This can be done by calling 'vxlan_skb_is_vxlan_v4'
 *
 */
static __always_inline __u32
vxlan_get_vni(const void *data, const void *data_end,
	      const struct iphdr *ipv4)
{
	int l3_size = ipv4->ihl * 4;
	struct vxlanhdr *hdr;

	if (data + sizeof(struct ethhdr) + l3_size + sizeof(struct udphdr)
	    + sizeof(struct vxlanhdr) > data_end)
		return 0;

	hdr = (struct vxlanhdr *)(data + sizeof(struct ethhdr) + l3_size +
	       sizeof(struct udphdr));

	return tunnel_vni_to_sec_identity(hdr->vx_vni);
}

/*
 * Points 'inner' to the inner IPv4 header of a IPv4 VXLan excapsulated
 * packet.
 *
 * The caller should be sure the VXLan packet is encapsulating IPv4 traffic
 * before calling this method.
 *
 * Returns 'true' if 'inner' now points to a bounds-checked inner IPv4 header.
 * Returns 'false' if an error occurred.
 */
static __always_inline bool
vxlan_get_inner_ipv4(const void *data, const void *data_end,
		     const struct iphdr *ipv4, struct iphdr **inner) {
	int l3_size = ipv4->ihl * 4;

	if (data + sizeof(struct ethhdr) + l3_size + sizeof(struct udphdr)
	    + sizeof(struct vxlanhdr) + sizeof(struct ethhdr) +
	    sizeof(struct iphdr) > data_end)
		return false;

	*inner = (struct iphdr *)(data + sizeof(struct ethhdr)
		  + l3_size + sizeof(struct udphdr) + sizeof(struct vxlanhdr)
		  + sizeof(struct ethhdr));

	return true;
}

/*
 * Rewrites the current VNI in the VXLan header to the provided and updates
 * the l4 checksum if necessary.
 *
 * The VNI is in host endian format when supplied to this function.
 *
 * The caller must ensure the skb associated with these data buffers are infact
 * a vxlan encapsulated packet before invoking this function.
 *
 * This can be done by calling 'vxlan_skb_is_vxlan_v4'
 */
static __always_inline bool
vxlan_rewrite_vni(void *ctx, const void *data, const void *data_end,
		  const struct iphdr *ipv4, __u32 vni)
{
	struct csum_offset csum = {0};
	int l3_size = ipv4->ihl * 4;
	int l4_off = sizeof(struct ethhdr) + l3_size;
	struct udphdr *udp = NULL;
	struct vxlanhdr *vx = NULL;
	__be32 old_vni = 0;

	if (data + sizeof(struct ethhdr) + l3_size + sizeof(struct udphdr)
	    + sizeof(struct vxlanhdr) > data_end)
		return false;

	udp = (struct udphdr *)(data + sizeof(struct ethhdr) + l3_size);

	vx = (struct vxlanhdr *)(data + sizeof(struct ethhdr) + l3_size
	      + sizeof(struct udphdr));

	old_vni = vx->vx_vni;
	vx->vx_vni = bpf_htonl(vni << 8);

	/* per rfc768 if UDP's checksum is zero this indicates no checksum was
	 * computed at all, so don't bother recomputing if its zero.
	 */
	if (udp->check) {
		csum_l4_offset_and_flags(IPPROTO_UDP, &csum);
		if (csum_l4_replace(ctx, l4_off, &csum, old_vni, vx->vx_vni,
				    BPF_F_PSEUDO_HDR | sizeof(__u16)) < 0)
			return false;
	}

	return true;
}

#endif /* __LIB_VXLAN_H_ */
