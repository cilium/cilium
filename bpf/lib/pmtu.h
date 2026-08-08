/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Service PMTU relay for load-balanced service VIPs.
 *
 * When a load-balanced service replies to a client, packets are sourced from
 * the *service VIP*. If such a reply is dropped by a lower-MTU link on the
 * return path (e.g. a tunnel), the resulting ICMP "fragmentation needed" error
 * is addressed to the VIP. It arrives at some node (not necessarily the one
 * holding the flow, because of BGP/ECMP), where the LB datapath cannot classify
 * it (ICMP is not a service protocol) and passes it to the local stack, where
 * it is useless: the VIP is not a local socket and the endpoint that actually
 * needs to lower its PMTU never sees the error, so the connection black-holes.
 *
 * This helper intercepts those errors on the forward path (nodeport_lb4) and
 * relays them to the backend that owns the connection:
 *
 *   - DSR backend: re-derive the owning backend statelessly via the same Maglev
 *     hash used on the forward path (the hash excludes the VIP, so any node
 *     derives the same backend), rewrite the error to that backend and forward
 *     it there. The backend's kernel caches the reduced PMTU for the connection.
 *     This is stateless, so it works even when BGP/ECMP lands the error on a
 *     node that is not the one holding the flow.
 *
 *   - SNAT-mode backend: the backend was chosen statefully on the ingress node
 *     and only that node holds the service conntrack entry, so recovery is
 *     best-effort: the backend is read from the CT_SERVICE entry and the relay
 *     only fires when the error came back to the ingress node (common for
 *     single-entry / tunnel topologies). Under ECMP the error usually lands on
 *     another node, where no CT entry exists and the relay falls through.
 *
 * On success the helper rewrites the embedded packet and the outer destination
 * to the backend address and returns CTX_ACT_REDIRECT; the caller delivers the
 * packet to the backend (recircle for a local/native backend, encapsulate for a
 * remote backend in tunnel mode). No per-connection PMTU state is stored in the
 * datapath.
 */

#pragma once

#include "common.h"
#include "lb.h"
#include "nat.h"
#include "conntrack.h"

#ifdef ENABLE_IPV6
#include "ipv6.h"
#include "icmp6.h"
#endif

#ifdef ENABLE_SVC_ICMP_PMTU_RELAY

/* Bound the relay per service (rev_nat_index) so a spoofed frag-needed spray at
 * a VIP cannot amplify. 100 relayed errors/s per service, burstable to 1000, is
 * far above the handful a real connection produces at PMTU-discovery time.
 * Returns true to drop. */
static __always_inline bool
pmtu_relay_ratelimited(__u16 rev_nat_index)
{
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_SVC_ICMP_PMTU_RELAY,
	};
	const struct ratelimit_settings settings = {
		.bucket_size = 1000,
		.tokens_per_topup = 100,
		.topup_interval_ns = NSEC_PER_SEC,
	};

	rkey.key.svc_pmtu_relay.rev_nat_index = rev_nat_index;
	return !ratelimit_check_and_take(&rkey, &settings);
}

#ifdef ENABLE_IPV4

/* Returns true for the ICMPv4 error types that carry a PMTU signal. */
static __always_inline bool
icmp4_is_frag_needed(__u8 type, __u8 code)
{
	return type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED;
}

/*
 * handle_icmp_svc_pmtu_v4 - relay an ICMPv4 frag-needed addressed to a service
 * VIP to the DSR backend owning the connection.
 *
 * @l4_off: offset of the (outer) ICMP header.
 *
 * Returns CTX_ACT_REDIRECT (packet consumed, rewritten to the backend),
 * CTX_ACT_OK (not ours / not applicable -> caller keeps its default handling),
 * or a negative DROP_* code on hard error.
 */
static __always_inline int
handle_icmp_svc_pmtu_v4(struct __ctx_buff *ctx, struct iphdr *ip4, int l4_off,
			__s8 *ext_err __maybe_unused)
{
	__u32 inner_l3_off = (__u32)(l4_off + sizeof(struct icmphdr));
	struct icmphdr icmphdr __align_stack_8;
	struct iphdr inner;
	struct lb4_key key = {};
	const struct lb4_service *svc;
	const struct lb4_backend *backend;
	struct ipv4_ct_tuple tuple = {};
	__be16 svc_port = 0, client_port = 0;
	__u32 backend_id;
	__u32 icmp_l4_off;
	int ret;

	if (ip4->protocol != IPPROTO_ICMP)
		return CTX_ACT_OK;

	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		return DROP_INVALID;
	if (!icmp4_is_frag_needed(icmphdr.type, icmphdr.code))
		return CTX_ACT_OK;

	/* Inner packet = the original reply the backend sent:
	 * src = VIP:svc_port, dst = client:client_port. (RFC 5508)
	 */
	if (ctx_load_bytes(ctx, inner_l3_off, &inner, sizeof(inner)) < 0)
		return DROP_INVALID;

	/* Only TCP/UDP services participate. */
	switch (inner.protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		break;
	default:
		return CTX_ACT_OK;
	}

	icmp_l4_off = inner_l3_off + ipv4_hdrlen(&inner);
	/* Inner L4 ports: sport = svc_port (from the VIP side), dport = client. */
	if (ctx_load_bytes(ctx, icmp_l4_off, &svc_port, sizeof(svc_port)) < 0)
		return DROP_INVALID;
	if (ctx_load_bytes(ctx, icmp_l4_off + 2, &client_port, sizeof(client_port)) < 0)
		return DROP_INVALID;

	/* Service lookup keyed on the inner packet's VIP:svc_port. */
	key.address = inner.saddr;
	key.dport = svc_port;
	key.proto = inner.protocol;

	/* Only an error addressed to the VIP is handled: its outer destination is
	 * the VIP, which equals the embedded packet's source. */
	if (ip4->daddr != inner.saddr)
		return CTX_ACT_OK;

	svc = lb4_lookup_service(&key, false);
	if (!svc)
		return CTX_ACT_OK;			/* not a service VIP */

	/* L7/Ingress services terminate at a cilium-envoy proxy, not at the
	 * backend the datapath would resolve, so the L4 relay must not touch
	 * them. They carry SVC_FLAG_FWD_MODE_DSR on DSR clusters, so without
	 * this guard they would fall into the DSR branch and the error would be
	 * misdelivered to an arbitrary backend. Leave them for the stack. */
	if (lb4_svc_is_l7_loadbalancer(svc))
		return CTX_ACT_OK;

	if (pmtu_relay_ratelimited(svc->rev_nat_index))
		return DROP_RATE_LIMITED;

	/* Build the flow tuple once; both the DSR and SNAT paths key on it.
	 *
	 * Handedness matches lb4_local() / lb4_select_backend_id_maglev(): the
	 * ports are stored swapped (sport = svc_port, dport = client_port) and the
	 * hash uses tuple->saddr = client. This equals the forward path's tuple
	 * (saddr = client, sport = client_port, dport = svc_port before the swap),
	 * so the Maglev result and the CT_SERVICE key both match the ingress node.
	 */
	tuple.saddr = inner.daddr;		/* client */
	tuple.daddr = inner.saddr;		/* VIP */
	tuple.nexthdr = inner.protocol;
	tuple.sport = svc_port;
	tuple.dport = client_port;

	if (svc->flags2 & SVC_FLAG_FWD_MODE_DSR) {
		/* DSR: re-derive the backend statelessly. Only the Maglev hash
		 * excludes the VIP, so the (arbitrary) node the ICMP lands on picks
		 * the same backend the ingress node did. Under any other algorithm
		 * (e.g. random) the re-derived backend would differ, so skip. */
		{
		__u32 alg = lb4_algorithm(svc);

		if (alg != LB_SELECTION_MAGLEV && alg != LB_SELECTION_RANDOM &&
		    alg != LB_SELECTION_FIRST)
			alg = lb_default_algorithm();
		if (alg != LB_SELECTION_MAGLEV)
			return CTX_ACT_OK;
		}
		backend_id = lb4_select_backend_id(ctx, &key, &tuple, svc);
	} else {
		/* SNAT-mode: the backend was chosen statefully on the ingress node
		 * and only that node holds the service conntrack entry, so this is
		 * best-effort -- it can only relay when the error came back to the
		 * ingress node (typical for single-entry / tunnel topologies; never
		 * under ECMP, where the error lands elsewhere and we fall through).
		 * Recover the backend by repeating lb4_local()'s CT_SERVICE lookup
		 * with the same tuple, so the key matches; the embedded reply's L4
		 * header sits at icmp_l4_off. */
		/* rev_nat_index must be set for the CT_SERVICE match (see
		 * ct_entry_matches_types()); lb4_local() sets it before the lookup. */
		struct ct_state ct_state = { .rev_nat_index = svc->rev_nat_index };
		__u32 monitor = 0;

		/* We already parsed the ports into the tuple, so tell CT not to read
		 * the embedded L4 header (it may be truncated in the ICMP payload):
		 * this is a pure, side-effect-free key lookup. */
		ret = ct_lazy_lookup4(get_ct_map4(&tuple), &tuple, ctx,
				      IPFRAG_BIT_NO_L4_HEADER, (int)icmp_l4_off,
				      CT_SERVICE, SCOPE_REVERSE, CT_ENTRY_SVC,
				      &ct_state, &monitor);
		if (ret != CT_REPLY)
			return CTX_ACT_OK;	/* no local CT entry: not the ingress node */
		backend_id = ct_state.backend_id;
	}

	if (!backend_id)
		return CTX_ACT_OK;
	backend = __lb4_lookup_backend(backend_id);
	if (!backend)
		return CTX_ACT_OK;

	/* Reverse the DSR DNAT on the embedded (inner) packet so the backend
	 * kernel matches the error to its socket (backend:backend_port <-> client):
	 * rewrite inner src VIP:svc_port -> backend->address:backend->port (fixing
	 * the inner IP + inner L4 checksums), then rewrite the OUTER dst VIP ->
	 * backend and amend the OUTER ICMP checksum for the embedded change. This
	 * mirrors snat_v4_rev_nat_handle_icmp_error() + snat_v4_rev_nat()'s two-step
	 * rewrite: fixing only the inner checksums leaves the outer ICMP checksum
	 * stale and the backend kernel silently drops the error.
	 */
	{
		__u32 total_inner_len = (__u32)ctx_full_len(ctx) - inner_l3_off;
		bool has_inner_l4_csum = true;
		__wsum outer_csum_diff = 0;

		/* A frag-needed error may embed only the IP header + 8 L4 bytes,
		 * which is too short to carry the inner L4 checksum. */
		if (inner.protocol == IPPROTO_TCP &&
		    total_inner_len < ipv4_hdrlen(&inner) + TCP_CSUM_OFF + sizeof(__u16))
			has_inner_l4_csum = false;

		/* For UDP a checksum of 0 means "no checksum"; treat it as absent
		 * so the outer ICMP diff accounts for the port change only (the
		 * address change is cancelled by the inner IP checksum). Matches
		 * snat_v4_rev_nat_handle_icmp_error(). */
		if (inner.protocol == IPPROTO_UDP) {
			__be16 l4_csum = 0;

			if (ctx_load_bytes(ctx, icmp_l4_off + offsetof(struct udphdr, check),
					   &l4_csum, sizeof(l4_csum)) < 0)
				return DROP_INVALID;
			if (l4_csum == 0)
				has_inner_l4_csum = false;
		}

		snat_v4_calc_icmp_error_csum_diff(inner.saddr, backend->address,
						  svc_port, backend->port,
						  has_inner_l4_csum, &outer_csum_diff);

		/* (1) Rewrite the embedded packet. */
		ret = snat_v4_rewrite_headers(ctx, inner.protocol, (int)inner_l3_off,
					      true, (int)icmp_l4_off,
					      inner.saddr, backend->address, IPV4_SADDR_OFF,
					      svc_port, backend->port, TCP_SPORT_OFF, 0);
		if (!has_inner_l4_csum && ret == DROP_CSUM_L4)
			ret = 0;
		if (IS_ERR(ret))
			return ret;

		/* (2) Rewrite the outer IP dst VIP -> backend (so normal pod routing
		 * delivers to the backend) and amend the outer ICMP checksum. The old
		 * outer daddr == VIP == inner.saddr, a stack value (the packet pointer
		 * is stale after the write above). No outer port change. */
		ret = snat_v4_rewrite_headers(ctx, IPPROTO_ICMP, ETH_HLEN, true,
					      (int)l4_off,
					      inner.saddr, backend->address, IPV4_DADDR_OFF,
					      0, 0, 0, outer_csum_diff);
		if (IS_ERR(ret))
			return ret;
	}

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);

	/* Delivery: the outer destination now points at the backend, so return
	 * CTX_ACT_REDIRECT and let the caller recircle through from-netdev, where
	 * normal pod routing delivers to the backend (local endpoint or remote
	 * node) without needing a backend-local vs -remote distinction here.
	 */
	return CTX_ACT_REDIRECT;
}

#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6

/*
 * IPv6 counterpart. The mechanics mirror the IPv4 path with two differences:
 *  - the trigger is ICMPv6 "packet too big" (ICMPV6_PKT_TOOBIG);
 *  - the ICMPv6 checksum has a pseudo-header, so every outer-address rewrite
 *    must amend it. snat_v6_rewrite_headers() does that (it applies the address
 *    diff at the ICMPv6 checksum offset with BPF_F_PSEUDO_HDR), so the outer
 *    destination is rewritten through it rather than by hand. The embedded
 *    rewrite needs no separate outer-checksum fix: IPv6 has no L3 checksum, so
 *    the embedded address change and the embedded L4 checksum change cancel out
 *    in the enclosing ICMPv6 checksum (same reasoning as the stock
 *    snat_v6_rev_nat_handle_icmp_pkt_toobig()).
 */
static __always_inline int
handle_icmp_svc_pmtu_v6(struct __ctx_buff *ctx, struct ipv6hdr *ip6, int l4_off,
			__s8 *ext_err __maybe_unused)
{
	__u32 inner_l3_off = (__u32)(l4_off + sizeof(struct icmp6hdr));
	struct ipv6hdr inner;
	struct lb6_key key = {};
	const struct lb6_service *svc;
	const struct lb6_backend *backend;
	struct ipv6_ct_tuple tuple __align_stack_8 = {};
	union v6addr vip, baddr;
	__be16 svc_port = 0, client_port = 0;
	__u8 inner_nexthdr, type;
	__u32 backend_id, icmp_l4_off;
	int hdrlen, ret;

	if (icmp6_load_type(ctx, l4_off, &type) < 0)
		return DROP_INVALID;
	if (type != ICMPV6_PKT_TOOBIG)
		return CTX_ACT_OK;

	/* Inner packet = the original reply: src = VIP:svc_port, dst = client. */
	if (ctx_load_bytes(ctx, inner_l3_off, &inner, sizeof(inner)) < 0)
		return DROP_INVALID;

	inner_nexthdr = inner.nexthdr;
	hdrlen = ipv6_hdrlen_offset(ctx, (int)inner_l3_off, &inner_nexthdr, NULL);
	if (hdrlen < 0)
		return DROP_INVALID;
	icmp_l4_off = inner_l3_off + (__u32)hdrlen;

	switch (inner_nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		break;
	default:
		return CTX_ACT_OK;
	}

	if (ctx_load_bytes(ctx, icmp_l4_off, &svc_port, sizeof(svc_port)) < 0)
		return DROP_INVALID;
	if (ctx_load_bytes(ctx, icmp_l4_off + 2, &client_port, sizeof(client_port)) < 0)
		return DROP_INVALID;

	ipv6_addr_copy(&vip, (union v6addr *)&inner.saddr);

	/* Sanity: only handle an error addressed to the VIP that sourced the
	 * dropped packet (outer dst == embedded src). */
	if (!ipv6_addr_equals((union v6addr *)&ip6->daddr, &vip))
		return CTX_ACT_OK;

	ipv6_addr_copy(&key.address, &vip);
	key.dport = svc_port;
	key.proto = inner_nexthdr;

	svc = lb6_lookup_service(&key, false);
	if (!svc)
		return CTX_ACT_OK;

	/* L7/Ingress services are handled by cilium-envoy, not the resolved
	 * backend; skip them so the L4 relay does not misdeliver the error (see
	 * the IPv4 path). */
	if (lb6_svc_is_l7_loadbalancer(svc))
		return CTX_ACT_OK;

	if (pmtu_relay_ratelimited(svc->rev_nat_index))
		return DROP_RATE_LIMITED;

	/* Rewriting the embedded packet keeps the outer ICMPv6 checksum valid only
	 * because the embedded address change and the embedded L4 checksum change
	 * cancel (IPv6 has no L3 checksum). A UDP reply with checksum 0 ("no
	 * checksum") has no L4 checksum to cancel the address/port change, so the
	 * rewrite would leave the outer ICMPv6 checksum wrong and the backend would
	 * drop the relayed error. Don't emit a malformed error for that rare case;
	 * fall through to the previous behavior. (The stock
	 * snat_v6_rev_nat_handle_icmp_pkt_toobig() shares this limitation; fully
	 * supporting it needs an outer-checksum diff in the shared helper.) */
	if (inner_nexthdr == IPPROTO_UDP) {
		__be16 l4_csum = 0;

		if (ctx_load_bytes(ctx, (int)(icmp_l4_off + offsetof(struct udphdr, check)),
				   &l4_csum, sizeof(l4_csum)) < 0)
			return DROP_INVALID;
		if (l4_csum == 0)
			return CTX_ACT_OK;
	}

	/* Build the flow tuple once; both paths key on it (see the IPv4 path for
	 * the handedness rationale). */
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&inner.daddr);	/* client */
	ipv6_addr_copy(&tuple.daddr, &vip);				/* VIP */
	tuple.nexthdr = inner_nexthdr;
	tuple.sport = svc_port;
	tuple.dport = client_port;

	if (svc->flags2 & SVC_FLAG_FWD_MODE_DSR) {
		/* DSR: re-derive the backend statelessly. Only Maglev picks the same
		 * backend on any node (see the IPv4 path). */
		{
		__u32 alg = lb6_algorithm(svc);

		if (alg != LB_SELECTION_MAGLEV && alg != LB_SELECTION_RANDOM &&
		    alg != LB_SELECTION_FIRST)
			alg = lb_default_algorithm();
		if (alg != LB_SELECTION_MAGLEV)
			return CTX_ACT_OK;
		}
		backend_id = lb6_select_backend_id(ctx, &key, &tuple, svc);
	} else {
		/* SNAT-mode: best-effort recovery from the service conntrack entry,
		 * which only exists on the ingress node (see the IPv4 path). */
		struct ct_state ct_state = { .rev_nat_index = svc->rev_nat_index };
		__u32 monitor = 0;

		ret = ct_lazy_lookup6(get_ct_map6(&tuple), &tuple, ctx,
				      IPFRAG_BIT_NO_L4_HEADER, (int)icmp_l4_off,
				      CT_SERVICE, SCOPE_REVERSE, CT_ENTRY_SVC,
				      &ct_state, &monitor);
		if (ret != CT_REPLY)
			return CTX_ACT_OK;	/* no local CT entry: not the ingress node */
		backend_id = ct_state.backend_id;
	}

	if (!backend_id)
		return CTX_ACT_OK;
	backend = __lb6_lookup_backend(backend_id);
	if (!backend)
		return CTX_ACT_OK;
	ipv6_addr_copy(&baddr, (union v6addr *)&backend->address);

	/* (1) Rewrite the embedded packet: inner src VIP:svc_port -> backend.
	 * The embedded L4 checksum is fixed; the outer ICMPv6 checksum is left
	 * unchanged (the inner address and inner L4 checksum changes cancel). */
	ret = snat_v6_rewrite_headers(ctx, inner_nexthdr, (int)inner_l3_off, true,
				      (int)icmp_l4_off, &vip, &baddr,
				      IPV6_SADDR_OFF, svc_port, backend->port,
				      TCP_SPORT_OFF);
	if (IS_ERR(ret))
		return ret;

	/* (2) Rewrite the outer dst VIP -> backend and amend the ICMPv6 checksum
	 * for the address change. old outer daddr == VIP == vip (stack value). */
	ret = snat_v6_rewrite_headers(ctx, IPPROTO_ICMPV6, ETH_HLEN, true, l4_off,
				      &vip, &baddr, IPV6_DADDR_OFF, 0, 0, 0);
	if (IS_ERR(ret))
		return ret;

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);

	return CTX_ACT_REDIRECT;
}

#endif /* ENABLE_IPV6 */

#endif /* ENABLE_SVC_ICMP_PMTU_RELAY */
