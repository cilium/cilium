/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>

#define TCP_CSUM_OFF	(offsetof(struct tcphdr, check))
#define TCP_CSUM_SIZE	(field_sizeof(struct tcphdr, check))
#define UDP_CSUM_OFF	(offsetof(struct udphdr, check))

struct csum_offset {
	__u16 offset;
	__u16 flags;
};

/**
 * Determins the L4 checksum field offset and required flags
 * @arg nexthdr	L3 nextheader field
 * @arg off	Pointer to uninitialied struct csum_offset struct
 *
 * Sets off.offset to offset from start of L4 header to L4 checksum field
 * and off.flags to the required flags, namely BPF_F_MARK_MANGLED_0 for UDP.
 * For unknown L4 protocols or L4 protocols which do not have a checksum
 * field, off is initialied to 0.
 */
static __always_inline void csum_l4_offset_and_flags(__u8 nexthdr,
						     struct csum_offset *off)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
		off->offset = TCP_CSUM_OFF;
		break;

	case IPPROTO_UDP:
		off->offset = UDP_CSUM_OFF;
		off->flags = BPF_F_MARK_MANGLED_0;
		break;
	case IPPROTO_SCTP:
		if (!CONFIG(enable_sctp))
			break;
		/* Disable readjusting checksums of SCTP packets.
		 * SCTP packets use a crc32c checksum over the SCTP
		 * header and the data and do not checksum the any
		 * part of the packet prior to the SCTP header.
		 * This means as long as we do not modify the ports
		 * the SCTP checksum will not change. We do this
		 * because there is not a good way to calculate a
		 * crc32c checksum in eBPF and will likely require
		 * additional kernel support.
		 */
		off->offset = 0;
		break;
	case IPPROTO_ICMPV6:
		off->offset = offsetof(struct icmp6hdr, icmp6_cksum);
		break;

	case IPPROTO_ICMP:
		break;
	}
}

/**
 * Helper to change L4 checksum
 * @arg ctx	Packet
 * @arg l4_off	Offset to L4 header
 * @arg csum	Pointer to csum_offset as extracted by csum_l4_offset_and_flags()
 * @arg from	From value or 0 if to contains csum diff
 * @arg to	To value or a csum diff
 * @arg flags	Additional flags to be passed to l4_csum_replace()
 */
static __always_inline int csum_l4_replace(struct __ctx_buff *ctx, __u64 l4_off,
					   const struct csum_offset *csum,
					   __be32 from, __be32 to, int flags)
{
	return l4_csum_replace(ctx, (__u32)(l4_off + csum->offset), from, to, flags | csum->flags);
}

/**
 * Helper to amend the L4 checksum after an IPv6 address change
 * @arg ctx	Packet
 * @arg l4_off	Offset to L4 header
 * @arg csum	Pointer to csum_offset as extracted by csum_l4_offset_and_flags()
 * @arg sum	csum_diff() of the old and new addresses
 *
 * The address change is in the pseudo-header, so it is matched by the change
 * of the L4 checksum and skb->csum of a CHECKSUM_COMPLETE skb must not move.
 * This assumes the address was written without BPF_F_RECOMPUTE_CSUM.
 * BPF_F_IPV6 tells bpf_l4_csum_replace() so. Kernels without that flag fail
 * with -EINVAL; with only BPF_F_PSEUDO_HDR they subtract sum from skb->csum,
 * which csum_update() adds back. Omitting BPF_F_PSEUDO_HDR instead would skip
 * the L4 checksum update for CHECKSUM_PARTIAL skbs.
 *
 * Without an L4 checksum over the pseudo-header (csum->offset == 0, e.g. a
 * non-first fragment or SCTP) nothing absorbs the address change, so
 * skb->csum has to follow it. That is wrong for the embedded packet of an
 * ICMPv6 error, where the outer ICMPv6 checksum absorbs it (see
 * snat_v6_calc_icmp_error_csum_diff()), so don't use this helper there with
 * csum->offset == 0.
 *
 * bpf_csum_update() only changes skb->csum when skb->ip_summed is
 * CHECKSUM_COMPLETE. Otherwise it is a no-op that returns -ENOTSUPP.
 */
static __always_inline int
csum_l4_replace_ipv6_addr(struct __ctx_buff *ctx, __u64 l4_off,
			  const struct csum_offset *csum, __be32 sum)
{
	int ret;

	if (!csum->offset) {
		csum_update(ctx, sum);
		return 0;
	}

	ret = csum_l4_replace(ctx, l4_off, csum, 0, sum,
			      BPF_F_PSEUDO_HDR | BPF_F_IPV6);
	if (ret != -EINVAL)
		return ret;

	ret = csum_l4_replace(ctx, l4_off, csum, 0, sum, BPF_F_PSEUDO_HDR);
	if (!ret)
		csum_update(ctx, sum);

	return ret;
}
