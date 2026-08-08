/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include "common.h"
#include "dbg.h"
#include "csum.h"
#include "identity.h"

#define TCP_DPORT_OFF (offsetof(struct tcphdr, dest))
#define TCP_SPORT_OFF (offsetof(struct tcphdr, source))
#define UDP_DPORT_OFF (offsetof(struct udphdr, dest))
#define UDP_SPORT_OFF (offsetof(struct udphdr, source))

union tcp_flags {
	struct {
		__u8 upper_bits;
		__u8 lower_bits;
		__u16 pad;
	};
	__u32 value;
};

static __always_inline __u8 tcp_flags_to_u8(__be32 value)
{
	return ((union tcp_flags)value).lower_bits;
}

static __always_inline bool tcp_is_syn(union tcp_flags flags)
{
	/* Match SYN, but not SYN-ACK. */
	return (flags.value & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN;
}

static __always_inline int
l4_store_port(struct __ctx_buff *ctx, int l4_off, int port_off, __be16 port)
{
	return ctx_store_bytes(ctx, l4_off + port_off, &port, sizeof(port), 0);
}

/**
 * Modify L4 port and correct checksum
 * @arg ctx:      packet
 * @arg l4_off:   offset to L4 header
 * @arg off:      offset from L4 header to source or destination port
 * @arg csum_off: offset from L4 header to 16bit checksum field in L4 header
 * @arg port:     new port value
 * @arg old_port: old port value (for checksum correction)
 *
 * Overwrites a TCP or UDP port with new value and fixes up the checksum
 * in the L4 header and of ctx->csum.
 *
 * NOTE: Calling this function will invalidate any pkt context offset
 * validation for direct packet access.
 *
 * Return 0 on success or a negative DROP_* reason
 */
static __always_inline int l4_modify_port(struct __ctx_buff *ctx, int l4_off,
					  int off, struct csum_offset *csum_off,
					  __be16 port, __be16 old_port)
{
	if (ctx_store_bytes(ctx, l4_off + off, &port, sizeof(port), 0) < 0)
		return DROP_WRITE_ERROR;

	if (csum_l4_replace(ctx, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
		return DROP_CSUM_L4;

	return 0;
}

/**
 * Rewrite the L4 port (if changed) and amend the L4 checksum for both the
 * port change and a paired L3 address change already applied by the caller,
 * folding in an extra checksum diff for the embedded packet of an ICMP error.
 * @arg ctx:      packet
 * @arg nexthdr:  L4 protocol
 * @arg l4_off:   offset to L4 header
 * @arg port_off: offset from L4 header to source or destination port
 * @arg old_port: old port value (for checksum correction), 0 if unused
 * @arg new_port: new port value, equal to old_port if unused
 * @arg l3_sum:   checksum diff of the paired L3 address change, 0 if none
 * @arg l4_csum_diff_from_inner: extra L4 checksum diff to apply (for ICMP
 *      error messages), 0 if none
 *
 * Return 0 on success or a negative DROP_* reason
 */
static __always_inline int
l4_rewrite_port_and_csum(struct __ctx_buff *ctx, __u8 nexthdr, int l4_off, int port_off,
			 __be16 old_port, __be16 new_port, __wsum l3_sum,
			 __wsum l4_csum_diff_from_inner)
{
	struct csum_offset csum = {};
	int err;

	csum_l4_offset_and_flags(nexthdr, &csum);

	if (old_port != new_port) {
		switch (nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_ICMPV6:
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
		case IPPROTO_ICMP:
			/* Not initialized by csum_l4_offset_and_flags(), because ICMPv4
			 * doesn't use a pseudo-header, and the change in IP addresses is
			 * not supposed to change the L4 checksum.
			 * Set it temporarily to amend the checksum after changing ports.
			 */
			csum.offset = offsetof(struct icmphdr, checksum);
			break;
		default:
			return DROP_UNKNOWN_L4;
		}

		/* Amend the L4 checksum due to changing the ports. */
		err = l4_modify_port(ctx, l4_off, port_off, &csum, new_port, old_port);
		if (err < 0)
			return err;

		/* Restore the original offset. */
		if (nexthdr == IPPROTO_ICMP)
			csum.offset = 0;
	}

	/* Amend the L4 checksum due to changing the addresses. */
	if (csum.offset &&
	    csum_l4_replace(ctx, l4_off, &csum, 0, l3_sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	/* Apply additional L4 checksum diff if provided (for ICMP error messages). */
	if (l4_csum_diff_from_inner && !csum.offset) {
		csum.offset = offsetof(struct icmphdr, checksum);
		if (csum_l4_replace(ctx, l4_off, &csum, 0, l4_csum_diff_from_inner, 0) < 0)
			return DROP_CSUM_L4;
	}

	return 0;
}

static __always_inline int l4_load_port(const struct __ctx_buff *ctx, int off,
					__be16 *port)
{
	return ctx_load_bytes(ctx, off, port, sizeof(__be16));
}

static __always_inline int l4_load_ports(const struct __ctx_buff *ctx, int off,
					 __be16 *ports)
{
	return ctx_load_bytes(ctx, off, ports, 2 * sizeof(__be16));
}

static __always_inline int l4_load_tcp_flags(const struct __ctx_buff *ctx, int l4_off,
					     union tcp_flags *flags)
{
	return ctx_load_bytes(ctx, l4_off + 12, flags, 2);
}

/* A non-first fragment from the world whose first fragment (with the L4 ports)
 * was never seen can't be matched against policy, so it's dropped. On public
 * node IPs this is mostly ambient internet noise; report it under a distinct
 * reason so it can be told apart from in-cluster fragment bugs. Caller must
 * pass a resolved source identity.
 */
static __always_inline int
frag_not_found_world(int ret, __u32 src_sec_identity)
{
	if (ret == DROP_FRAG_NOT_FOUND && identity_is_world(src_sec_identity))
		return DROP_FRAG_NOT_FOUND_WORLD;
	return ret;
}
