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
 * This helper intercepts those errors on the forward path (nodeport_lb{4,6})
 * and, depending on the service forwarding mode:
 *
 *   - DSR backend: re-derive the owning backend statelessly via the same Maglev
 *     hash used on the forward path (the hash excludes the VIP, so any node
 *     derives the same backend), rewrite the error to that backend and forward
 *     it there. The backend's kernel caches the reduced PMTU for the connection.
 *
 *   - L7/Ingress (Envoy): the connection terminates at a proxy on one node that
 *     cannot be re-derived statelessly, so the error is left to the stack.
 *
 * No per-connection PMTU state is stored in the datapath.
 */

#pragma once

#include "common.h"
#include "lb.h"
#include "nat.h"
#include "conntrack.h"
#include "eps.h"
#include "l4.h"
#ifdef ENABLE_IPV6
#include "ipv6.h"
#include "icmp6.h"
#endif

/* The relay hooks into nodeport_lb{4,6}() on the from-netdev path of bpf_host
 * (TC) and bpf_xdp, the programs owning the CILIUM_CALL_IPV{4,6}_FROM_NETDEV
 * slot a relayed error recircles through. Every other object gets no-op stubs
 * so the call sites need no conditional compilation. */
#if defined(ENABLE_SVC_ICMP_PMTU_RELAY) && (defined(IS_BPF_HOST) || defined(IS_BPF_XDP))

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

/*
 * handle_icmp_svc_pmtu_v4 - relay an ICMPv4 frag-needed addressed to a service
 * VIP to the endpoint that must lower its PMTU.
 *
 * @l4_off: offset of the (outer) ICMP header.
 *
 * Returns CTX_ACT_REDIRECT (rewritten to the DSR backend; the caller recircles
 * it through from-netdev), CTX_ACT_OK (not ours / not applicable -> caller keeps
 * its default handling), or a DROP_* code.
 */
static __always_inline int
handle_icmp_svc_pmtu_v4(struct __ctx_buff *ctx, struct iphdr *ip4, int l4_off)
{
	__u32 inner_l3_off = (__u32)(l4_off + sizeof(struct icmphdr));
	struct icmphdr icmphdr __align_stack_8;
	struct iphdr inner;
	struct lb4_key key = {};
	const struct lb4_service *svc;
	const struct lb4_backend *backend;
	struct ipv4_ct_tuple tuple = {};
	__be16 ports[2];	/* embedded sport = svc_port, dport = client port */
	__be16 l4_csum = 0;
	__wsum outer_csum_diff;
	bool has_inner_l4_csum = true;
	__u32 backend_id, icmp_l4_off;
	int ret;

	if (ctx_load_bytes(ctx, l4_off, &icmphdr, sizeof(icmphdr)) < 0)
		return DROP_INVALID;
	if (icmphdr.type != ICMP_DEST_UNREACH || icmphdr.code != ICMP_FRAG_NEEDED)
		return CTX_ACT_OK;

	/* Inner packet = the original reply the backend sent:
	 * src = VIP:svc_port, dst = client:client_port. (RFC 5508)
	 */
	if (ctx_load_bytes(ctx, inner_l3_off, &inner, sizeof(inner)) < 0)
		return DROP_INVALID;

	/* Only the original error is handled: its outer destination is the VIP,
	 * which equals the embedded packet's source. Flooded L7 copies (below)
	 * carry a rewritten outer destination (a node IP), so they fall through
	 * here -- this is the loop guard for the flood. */
	if (ip4->daddr != inner.saddr)
		return CTX_ACT_OK;

	/* Only TCP/UDP services participate, and only a first fragment carries
	 * the embedded L4 ports. */
	if (inner.protocol != IPPROTO_TCP && inner.protocol != IPPROTO_UDP)
		return CTX_ACT_OK;
	if (!ipfrag_has_l4_header(ipfrag_encode_ipv4(&inner)))
		return CTX_ACT_OK;

	icmp_l4_off = inner_l3_off + ipv4_hdrlen(&inner);
	if (l4_load_ports(ctx, (int)icmp_l4_off, ports) < 0)
		return DROP_INVALID;

	key.address = inner.saddr;
	key.dport = ports[0];
	key.proto = inner.protocol;
	svc = lb4_lookup_service(&key, false);
	if (!svc)
		return CTX_ACT_OK;			/* not a service VIP */

	/* L7/Ingress services (which also carry the DSR flag) terminate at a
	 * cilium-envoy proxy whose node cannot be re-derived statelessly; the
	 * backend below would not own the connection, so leave the error alone. */
	if (lb4_svc_is_l7_loadbalancer(svc))
		return CTX_ACT_OK;

	/* L4 DSR: relay directly to the backend selected on this node. */
	if (!lb4_svc_uses_dsr(svc))
		return CTX_ACT_OK;			/* SNAT-mode: out of scope */

	/* Backend re-derivation must be deterministic across nodes: only the
	 * Maglev hash excludes the VIP, so the (arbitrary) node the ICMP lands on
	 * picks the same backend the ingress node did. Under any other algorithm
	 * (e.g. random) the re-derived backend would differ, so skip the relay. */
	if (lb_resolve_algorithm(lb4_algorithm(svc)) != LB_SELECTION_MAGLEV)
		return CTX_ACT_OK;

	/* Re-derive the same backend the ingress node picked. The Maglev hash
	 * is a pure function of (client addr, client port, svc port, proto) and
	 * excludes the VIP, so any node computes the same result.
	 *
	 * Tuple handedness matches lb4_local()'s call into
	 * lb4_select_backend_id_maglev(): there sport = tuple->dport,
	 * dport = tuple->sport, and the hash uses tuple->saddr. We therefore set
	 * saddr = client, sport = svc_port, dport = client_port so the hashed
	 * inputs equal the forward path's (saddr=client, sport=client_port,
	 * dport=svc_port after the port swap).
	 */
	tuple.saddr = inner.daddr;		/* client */
	tuple.daddr = inner.saddr;		/* VIP */
	tuple.nexthdr = inner.protocol;
	tuple.sport = ports[0];
	tuple.dport = ports[1];

	/* A sticky client may be pinned to a backend Maglev no longer maps it
	 * to; prefer the pin when this node holds it, as lb4_local() does. */
	backend_id = 0;
	if (lb4_svc_is_affinity(svc)) {
		union lb4_affinity_client_id client_id = {
			.client_ip = tuple.saddr,
		};

		backend_id = lb4_affinity_backend_id_peek(svc, &client_id);
	}
	if (!backend_id)
		backend_id = lb4_select_backend_id(ctx, &key, &tuple, svc);
	if (!backend_id)
		return CTX_ACT_OK;
	backend = __lb4_lookup_backend(backend_id);
	if (!backend)
		return CTX_ACT_OK;
#if DSR_ENCAP_MODE != DSR_ENCAP_NONE
	/* Backends behind DSR encapsulation are not natively routable from this
	 * node, so recircling can only deliver to a local backend. */
	if (!__lookup_ip4_endpoint(backend->address))
		return CTX_ACT_OK;
#endif

	if (pmtu_relay_ratelimited(svc->rev_nat_index))
		return DROP_RATE_LIMITED;

	/* Reverse the DSR DNAT on the embedded (inner) packet so the backend
	 * kernel matches the error to its socket (backend:backend_port <-> client):
	 * rewrite inner src VIP:svc_port -> backend->address:backend->port (fixing
	 * the inner IP + inner L4 checksums), then rewrite the OUTER dst VIP ->
	 * backend and amend the OUTER ICMP checksum for the embedded change. This
	 * mirrors snat_v4_rev_nat_handle_icmp_error() + snat_v4_rev_nat()'s two-step
	 * rewrite: fixing only the inner checksums leaves the outer ICMP checksum
	 * stale and the backend kernel silently drops the error.
	 *
	 * A frag-needed error may embed only the IP header + 8 L4 bytes, which is
	 * too short to carry the inner L4 checksum. */
	if (inner.protocol == IPPROTO_TCP &&
	    (__u32)ctx_full_len(ctx) - inner_l3_off <
	    ipv4_hdrlen(&inner) + TCP_CSUM_OFF + TCP_CSUM_SIZE)
		has_inner_l4_csum = false;

	/* For UDP a checksum of 0 means "no checksum"; treat it as absent so the
	 * outer ICMP diff accounts for the port change only (the address change
	 * is cancelled by the inner IP checksum). Matches
	 * snat_v4_rev_nat_handle_icmp_error(). */
	if (inner.protocol == IPPROTO_UDP) {
		if (udp_load_csum(ctx, (int)icmp_l4_off, &l4_csum) < 0)
			return DROP_INVALID;
		if (l4_csum == 0)
			has_inner_l4_csum = false;
	}

	outer_csum_diff = snat_v4_calc_icmp_error_csum_diff(inner.saddr,
							    backend->address,
							    ports[0], backend->port,
							    has_inner_l4_csum);

	/* (1) Rewrite the embedded packet. */
	ret = snat_v4_rewrite_headers(ctx, inner.protocol, (int)inner_l3_off,
				      true, (int)icmp_l4_off,
				      inner.saddr, backend->address, IPV4_SADDR_OFF,
				      ports[0], backend->port, TCP_SPORT_OFF, 0);
	if (!has_inner_l4_csum && ret == DROP_CSUM_L4)
		ret = 0;
	if (IS_ERR(ret))
		return ret;

	/* (2) Rewrite the outer IP dst VIP -> backend and amend the outer ICMP
	 * checksum. The old outer daddr == VIP == inner.saddr, a stack value (the
	 * packet pointer is stale after the write above). No outer port change. */
	ret = snat_v4_rewrite_headers(ctx, IPPROTO_ICMP, ETH_HLEN, true, l4_off,
				      inner.saddr, backend->address, IPV4_DADDR_OFF,
				      0, 0, 0, outer_csum_diff);
	if (IS_ERR(ret))
		return ret;

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);

	/* The outer destination now points at the backend: the caller recircles
	 * through from-netdev, where normal pod routing delivers to the backend
	 * (local endpoint or remote node). */
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
 *    destination is rewritten through it. The embedded rewrite needs no
 *    separate outer-checksum fix: IPv6 has no L3 checksum, so the embedded
 *    address change and the embedded L4 checksum change cancel out in the
 *    enclosing ICMPv6 checksum (as in snat_v6_rev_nat_handle_icmp_pkt_toobig()).
 */
static __always_inline int
handle_icmp_svc_pmtu_v6(struct __ctx_buff *ctx, struct ipv6hdr *ip6, int l4_off)
{
	__u32 inner_l3_off = (__u32)(l4_off + sizeof(struct icmp6hdr));
	struct ipv6hdr inner;
	struct lb6_key key = {};	/* key.address == the VIP */
	const struct lb6_service *svc;
	const struct lb6_backend *backend;
	struct ipv6_ct_tuple tuple __align_stack_8 = {};
	union v6addr backend_addr;
	__be16 ports[2];	/* embedded sport = svc_port, dport = client port */
	__be16 l4_csum = 0;
	__u8 inner_nexthdr, type;
	__u32 backend_id, icmp_l4_off;
	fraginfo_t fraginfo;
	int hdrlen, ret;

	if (icmp6_load_type(ctx, l4_off, &type) < 0)
		return DROP_INVALID;
	if (type != ICMPV6_PKT_TOOBIG)
		return CTX_ACT_OK;

	/* Inner packet = the original reply: src = VIP:svc_port, dst = client. */
	if (ctx_load_bytes(ctx, inner_l3_off, &inner, sizeof(inner)) < 0)
		return DROP_INVALID;

	/* Loop guard: only the original error, addressed to the VIP that sourced
	 * the embedded packet (see the IPv4 path). */
	if (!ipv6_addr_equals((union v6addr *)&ip6->daddr,
			      (union v6addr *)&inner.saddr))
		return CTX_ACT_OK;

	inner_nexthdr = inner.nexthdr;
	hdrlen = ipv6_hdrlen_offset(ctx, (int)inner_l3_off, &inner_nexthdr,
				    &fraginfo);
	if (hdrlen < 0)
		return DROP_INVALID;
	icmp_l4_off = inner_l3_off + (__u32)hdrlen;

	if (inner_nexthdr != IPPROTO_TCP && inner_nexthdr != IPPROTO_UDP)
		return CTX_ACT_OK;
	if (!ipfrag_has_l4_header(fraginfo))
		return CTX_ACT_OK;
	if (l4_load_ports(ctx, (int)icmp_l4_off, ports) < 0)
		return DROP_INVALID;

	ipv6_addr_copy(&key.address, (union v6addr *)&inner.saddr);
	key.dport = ports[0];
	key.proto = inner_nexthdr;
	svc = lb6_lookup_service(&key, false);
	if (!svc)
		return CTX_ACT_OK;

	if (lb6_svc_is_l7_loadbalancer(svc))
		return CTX_ACT_OK;			/* see the IPv4 path */

	if (!lb6_svc_uses_dsr(svc))
		return CTX_ACT_OK;			/* SNAT-mode: out of scope */

	/* Only Maglev re-derives the same backend on any node (see IPv4 path). */
	if (lb_resolve_algorithm(lb6_algorithm(svc)) != LB_SELECTION_MAGLEV)
		return CTX_ACT_OK;

	/* Rewriting the embedded packet keeps the outer ICMPv6 checksum valid only
	 * because the embedded address change and the embedded L4 checksum change
	 * cancel (IPv6 has no L3 checksum). A UDP reply with checksum 0 ("no
	 * checksum") has no L4 checksum to cancel the address/port change, so the
	 * rewrite would leave the outer ICMPv6 checksum wrong and the backend would
	 * drop the relayed error. Don't emit a malformed error for that rare case;
	 * leave it to the stack. Likewise when the error embeds only the first 8
	 * L4 bytes: the embedded TCP checksum is absent. */
	if (inner_nexthdr == IPPROTO_UDP) {
		if (udp_load_csum(ctx, (int)icmp_l4_off, &l4_csum) < 0)
			return DROP_INVALID;
		if (l4_csum == 0)
			return CTX_ACT_OK;
	}
	if (inner_nexthdr == IPPROTO_TCP &&
	    (__u32)ctx_full_len(ctx) - inner_l3_off <
	    (__u32)hdrlen + TCP_CSUM_OFF + TCP_CSUM_SIZE)
		return CTX_ACT_OK;

	/* Re-derive the backend statelessly (Maglev; see the IPv4 path). */
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&inner.daddr);	/* client */
	ipv6_addr_copy(&tuple.daddr, &key.address);			/* VIP */
	tuple.nexthdr = inner_nexthdr;
	tuple.sport = ports[0];
	tuple.dport = ports[1];

	/* Prefer the affinity pin when this node holds it (see the IPv4 path). */
	backend_id = 0;
	if (lb6_svc_is_affinity(svc)) {
		union lb6_affinity_client_id client_id;

		ipv6_addr_copy(&client_id.client_ip, &tuple.saddr);
		backend_id = lb6_affinity_backend_id_peek(svc, &client_id);
	}
	if (!backend_id)
		backend_id = lb6_select_backend_id(ctx, &key, &tuple, svc);
	if (!backend_id)
		return CTX_ACT_OK;
	backend = __lb6_lookup_backend(backend_id);
	if (!backend)
		return CTX_ACT_OK;
	ipv6_addr_copy(&backend_addr, (union v6addr *)&backend->address);
#if DSR_ENCAP_MODE != DSR_ENCAP_NONE
	if (!__lookup_ip6_endpoint(&backend_addr))
		return CTX_ACT_OK;	/* see the IPv4 path */
#endif

	if (pmtu_relay_ratelimited(svc->rev_nat_index))
		return DROP_RATE_LIMITED;

	/* (1) Rewrite the embedded packet: inner src VIP:svc_port -> backend.
	 * The embedded L4 checksum is fixed; the outer ICMPv6 checksum is left
	 * unchanged (the inner address and inner L4 checksum changes cancel). */
	ret = snat_v6_rewrite_headers(ctx, inner_nexthdr, (int)inner_l3_off, true,
				      (int)icmp_l4_off, &key.address, &backend_addr,
				      IPV6_SADDR_OFF, ports[0], backend->port,
				      TCP_SPORT_OFF, 0);
	if (IS_ERR(ret))
		return ret;

	/* (2) Rewrite the outer dst VIP -> backend and amend the ICMPv6 checksum
	 * for the address change. The old outer daddr == VIP == key.address, a
	 * stack value. */
	ret = snat_v6_rewrite_headers(ctx, IPPROTO_ICMPV6, ETH_HLEN, true, l4_off,
				      &key.address, &backend_addr, IPV6_DADDR_OFF,
				      0, 0, 0, 0);
	if (IS_ERR(ret))
		return ret;

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, REASON_MTU_ERROR_MSG);
	return CTX_ACT_REDIRECT;
}

#endif /* ENABLE_IPV6 */

#else /* !(ENABLE_SVC_ICMP_PMTU_RELAY && (IS_BPF_HOST || IS_BPF_XDP)) */

static __always_inline int
handle_icmp_svc_pmtu_v4(struct __ctx_buff *ctx __maybe_unused,
			struct iphdr *ip4 __maybe_unused, int l4_off __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline int
handle_icmp_svc_pmtu_v6(struct __ctx_buff *ctx __maybe_unused,
			struct ipv6hdr *ip6 __maybe_unused, int l4_off __maybe_unused)
{
	return CTX_ACT_OK;
}

#endif /* ENABLE_SVC_ICMP_PMTU_RELAY && (IS_BPF_HOST || IS_BPF_XDP) */
