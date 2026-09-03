/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Reply to ICMP echo (ping) requests addressed to a service VIP.
 *
 * Cilium's eBPF load balancer never binds service VIPs to an interface, so an
 * ICMP echo-request to a LoadBalancer/ClusterIP VIP is classified as a
 * non-service protocol (lb4_extract_tuple -> DROP_UNSUPP_SERVICE_PROTO) and
 * falls through to the stack, where nothing owns the VIP -- so the VIP never
 * answers ping. kube-proxy/IPVS binds the VIP to a dummy device and therefore
 * does answer, so this is a visible behaviour gap when migrating to Cilium.
 *
 * When ENABLE_SVC_ICMP_ECHO_RESPONDER is set, the datapath answers echo
 * requests addressed to a known service VIP directly: it turns the request
 * into a reply in place (swap L2/L3, flip the ICMP echo type) and reflects it
 * back out the ingress interface. The reply is stateless, so any node that
 * receives the request can answer it. It is opt-in and rate-limited per VIP.
 *
 * The work is split in two so the packet writes stay off the shared
 * nodeport_lb4/lb6 code path: svc_icmp_echo_is_target_v{4,6}() is a reads-only
 * probe run inline in nodeport_lb4/lb6 (so it never invalidates the caller's
 * ip4/ip6 pointer for the verifier), and svc_icmp_echo_send_reply_v{4,6}() --
 * which does all the packet writes and reflects the reply -- runs in a
 * dedicated CILIUM_CALL_IPV{4,6}_SVC_ICMP_ECHO tail-call program, returning
 * immediately after the writes.
 */

#pragma once

#include "common.h"
#include "eth.h"
#include "ipv6.h"
#include "lb.h"
#include "ratelimit.h"
#include "csum.h"

#ifdef ENABLE_SVC_ICMP_ECHO_RESPONDER

/* Rate-limit the echo responder per VIP: 100 replies/s, burstable to 1000. For
 * IPv6 the caller folds the 128-bit VIP down to a 32-bit key (a collision only
 * means two VIPs share a bucket, which is harmless for rate-limiting). */
static __always_inline bool
svc_icmp_echo_ratelimited(__u32 vip)
{
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_SVC_ICMP_ECHO,
	};
	const struct ratelimit_settings settings = {
		.bucket_size = 1000,
		.tokens_per_topup = 100,
		.topup_interval_ns = NSEC_PER_SEC,
	};

	rkey.key.svc_icmp_echo.vip = vip;
	return !ratelimit_check_and_take(&rkey, &settings);
}

#ifdef ENABLE_IPV4
/*
 * svc_icmp_echo_is_target_v4 - is this an ICMPv4 echo-request to a service VIP?
 *
 * @l4_off: offset of the (outer) ICMP header.
 *
 * Reads only -- it never writes the packet, so the caller's ip4 pointer stays
 * valid for the verifier on the fall-through path. Returns 1 when the packet
 * is an echo-request addressed to a known service VIP (caller should hand it
 * to the reply tail-call), 0 when it is not ours (caller keeps its default
 * handling), or a negative DROP_* code on a malformed header.
 */
static __always_inline int
svc_icmp_echo_is_target_v4(struct __ctx_buff *ctx, struct iphdr *ip4, int l4_off)
{
	struct icmphdr icmphdr __align_stack_8;
	struct lb4_key key = {};

	if (ip4->protocol != IPPROTO_ICMP)
		return 0;

	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		return DROP_INVALID;
	/* Only echo-request; leave every other ICMP type (incl. the errors the
	 * PMTU relay handles) to the caller. */
	if (icmphdr.type != ICMP_ECHO)
		return 0;

	/* Is the destination a service VIP? LoadBalancer/ClusterIP frontends
	 * (external scope) parent a wildcard service entry keyed on the VIP
	 * address with a wildcard port/proto, so a single lookup answers
	 * "is this a VIP?" without needing an L4 port. */
	key.address = ip4->daddr;
	key.dport = LB_SVC_WILDCARD_DPORT;
	key.proto = LB_SVC_WILDCARD_PROTO;
	key.scope = LB_LOOKUP_SCOPE_EXT;
	if (!__lb4_lookup_service(&key))
		return 0;			/* not a service VIP */

	return 1;
}

/*
 * svc_icmp_echo_send_reply_v4 - craft and reflect the echo reply.
 *
 * Runs in the CILIUM_CALL_IPV4_SVC_ICMP_ECHO tail-call program, so it is
 * self-contained: it re-validates its own ip4 pointer and recomputes l4_off.
 * All the packet writes live here (never on the shared nodeport_lb4 path), and
 * the function returns immediately after them, so the verifier tolerates the
 * ip4 invalidation the writes cause.
 *
 * The caller (nodeport_lb4 via svc_icmp_echo_is_target_v4) has already
 * confirmed this is an echo-request to a service VIP.
 *
 * Returns CTX_ACT_REDIRECT (reply sent back out the ingress iface) or a
 * negative DROP_* code.
 */
static __always_inline int
svc_icmp_echo_send_reply_v4(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct icmphdr icmphdr __align_stack_8;
	union macaddr smac, dmac;
	__be32 saddr, daddr;
	__be16 check_be;
	__u32 new_check;
	__u8 reply_type = ICMP_ECHOREPLY;
	int l4_off;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		return DROP_INVALID;

	/* Capture the addresses up front: the packet writes below go through
	 * bpf_skb_store_bytes(), which invalidates the ip4 pointer for the
	 * verifier, so ip4 must not be dereferenced afterwards. */
	saddr = ip4->saddr;
	daddr = ip4->daddr;

	if (svc_icmp_echo_ratelimited(daddr))
		return DROP_RATE_LIMITED;

	/* Swap L2. */
	if (eth_load_saddr(ctx, smac.addr, 0) < 0 ||
	    eth_load_daddr(ctx, dmac.addr, 0) < 0)
		return DROP_INVALID;
	if (eth_store_daddr(ctx, smac.addr, 0) < 0 ||
	    eth_store_saddr(ctx, dmac.addr, 0) < 0)
		return DROP_WRITE_ERROR;

	/* Swap L3. A symmetric saddr<->daddr swap leaves the IPv4 header
	 * checksum unchanged (both are summed), so it need not be recomputed. */
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr),
			    &daddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr),
			    &saddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;

	/* Flip ICMP type 8 (echo) -> 0 (echo reply); code, id, seq and payload
	 * are preserved. The type sits in the high byte of the first 16-bit
	 * ICMP word, so that word drops by (8 << 8). The ICMPv4 checksum covers
	 * only the ICMP message (no pseudo-header) and is the one's-complement
	 * of the sum, so it rises by the same amount, with the end-around carry
	 * folded back in. */
	new_check = bpf_ntohs(icmphdr.checksum) + (ICMP_ECHO << 8);
	new_check = (new_check & 0xffff) + (new_check >> 16);
	check_be = bpf_htons((__u16)new_check);
	if (ctx_store_bytes(ctx, l4_off + offsetof(struct icmphdr, type),
			    &reply_type, sizeof(reply_type), 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, l4_off + offsetof(struct icmphdr, checksum),
			    &check_be, sizeof(check_be), 0) < 0)
		return DROP_WRITE_ERROR;

	/* Reflect the reply back out the interface it arrived on. */
	return redirect_self(ctx);
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
/*
 * svc_icmp_echo_is_target_v6 - is this an ICMPv6 echo-request to a service VIP?
 *
 * @l4_off: offset of the (outer) ICMPv6 header. The caller has already
 * established that the L4 protocol is ICMPv6.
 *
 * Reads only; same contract as the v4 variant.
 */
static __always_inline int
svc_icmp_echo_is_target_v6(struct __ctx_buff *ctx, struct ipv6hdr *ip6, int l4_off)
{
	struct icmp6hdr icmp6 __align_stack_8;
	struct lb6_key key = {};

	if (ctx_load_bytes(ctx, l4_off, &icmp6, sizeof(icmp6)) < 0)
		return DROP_INVALID;
	if (icmp6.icmp6_type != ICMPV6_ECHO_REQUEST)
		return 0;

	memcpy(&key.address, &ip6->daddr, sizeof(key.address));
	key.dport = LB_SVC_WILDCARD_DPORT;
	key.proto = LB_SVC_WILDCARD_PROTO;
	key.scope = LB_LOOKUP_SCOPE_EXT;
	if (!__lb6_lookup_service(&key))
		return 0;			/* not a service VIP */

	return 1;
}

/*
 * svc_icmp_echo_send_reply_v6 - craft and reflect the ICMPv6 echo reply.
 *
 * Runs in the CILIUM_CALL_IPV6_SVC_ICMP_ECHO tail-call program; self-contained
 * like the v4 variant. The caller has confirmed this is an ICMPv6 echo-request
 * to a service VIP.
 */
static __always_inline int
svc_icmp_echo_send_reply_v6(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct icmp6hdr icmp6 __align_stack_8;
	union macaddr smac, dmac;
	union v6addr saddr, daddr;
	__u8 nexthdr, reply_type = ICMPV6_ECHO_REPLY;
	__be16 check_be;
	__u32 new_check;
	int l4_off, hdrlen;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &nexthdr);
	if (hdrlen < 0)
		return DROP_INVALID;
	l4_off = ETH_HLEN + hdrlen;

	if (ctx_load_bytes(ctx, l4_off, &icmp6, sizeof(icmp6)) < 0)
		return DROP_INVALID;

	/* Capture the addresses before the packet writes below invalidate ip6. */
	memcpy(&saddr, &ip6->saddr, sizeof(saddr));
	memcpy(&daddr, &ip6->daddr, sizeof(daddr));

	if (svc_icmp_echo_ratelimited(daddr.p1 ^ daddr.p2 ^ daddr.p3 ^ daddr.p4))
		return DROP_RATE_LIMITED;

	/* Swap L2. */
	if (eth_load_saddr(ctx, smac.addr, 0) < 0 ||
	    eth_load_daddr(ctx, dmac.addr, 0) < 0)
		return DROP_INVALID;
	if (eth_store_daddr(ctx, smac.addr, 0) < 0 ||
	    eth_store_saddr(ctx, dmac.addr, 0) < 0)
		return DROP_WRITE_ERROR;

	/* Swap L3. The ICMPv6 checksum includes a pseudo-header over the source
	 * and destination addresses, but a symmetric swap leaves that sum
	 * unchanged, so only the type flip below affects the checksum. */
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    &daddr, sizeof(daddr), 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			    &saddr, sizeof(saddr), 0) < 0)
		return DROP_WRITE_ERROR;

	/* Flip ICMPv6 type 128 (echo request) -> 129 (echo reply). The type is
	 * the high byte of the first 16-bit word, so that word rises by (1 << 8);
	 * the one's-complement checksum therefore drops by the same amount, added
	 * here as its 16-bit complement with the end-around carry folded in. */
	new_check = bpf_ntohs(icmp6.icmp6_cksum) + (__u16)~(1 << 8);
	new_check = (new_check & 0xffff) + (new_check >> 16);
	new_check = (new_check & 0xffff) + (new_check >> 16);
	check_be = bpf_htons((__u16)new_check);
	if (ctx_store_bytes(ctx, l4_off + offsetof(struct icmp6hdr, icmp6_type),
			    &reply_type, sizeof(reply_type), 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, l4_off + offsetof(struct icmp6hdr, icmp6_cksum),
			    &check_be, sizeof(check_be), 0) < 0)
		return DROP_WRITE_ERROR;

	/* Reflect the reply back out the interface it arrived on. */
	return redirect_self(ctx);
}
#endif /* ENABLE_IPV6 */

#endif /* ENABLE_SVC_ICMP_ECHO_RESPONDER */
