// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "bpf/types_mapper.h"
#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include <ep_config.h>
#include <node_config.h>

#include <linux/icmpv6.h>

#define IS_BPF_LXC 1

#define EVENT_SOURCE LXC_ID

#include "lib/auth.h"
#include "lib/tailcall.h"
#include "lib/common.h"
#include "lib/config.h"
#include "lib/maps.h"
#include "lib/arp.h"
#include "lib/edt.h"
#include "lib/qm.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/lxc.h"
#include "lib/identity.h"
#include "lib/policy.h"
#include "lib/mcast.h"

/* Override LB_SELECTION initially defined in node_config.h to force bpf_lxc to use the random backend selection
 * algorithm for in-cluster traffic. Otherwise, it will fail with the Maglev hash algorithm because Cilium doesn't provision
 * the Maglev table for ClusterIP unless bpf.lbExternalClusterIP is set to true.
 */
#undef LB_SELECTION
#define LB_SELECTION LB_SELECTION_RANDOM

#include "lib/lb.h"
#include "lib/drop.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/csum.h"
#include "lib/egress_gateway.h"
#include "lib/srv6.h"
#include "lib/encap.h"
#include "lib/eps.h"
#include "lib/nat.h"
#include "lib/fib.h"
#include "lib/nodeport.h"
#include "lib/policy_log.h"

/* Per-packet LB is needed if all LB cases can not be handled in bpf_sock.
 * Most services with L7 LB flag can not be redirected to their proxy port
 * in bpf_sock, so we must check for those via per packet LB as well.
 * Furthermore, since SCTP cannot be handled as part of bpf_sock, also
 * enable per-packet LB is SCTP is enabled.
 */
#if !defined(ENABLE_SOCKET_LB_FULL) || \
    defined(ENABLE_SOCKET_LB_HOST_ONLY) || \
    defined(ENABLE_L7_LB)               || \
    defined(ENABLE_SCTP)                || \
    defined(ENABLE_CLUSTER_AWARE_ADDRESSING)
# define ENABLE_PER_PACKET_LB 1
#endif

#ifdef ENABLE_PER_PACKET_LB

#ifdef ENABLE_IPV4
static __always_inline int __per_packet_lb_svc_xlate_4(void *ctx, struct iphdr *ip4,
						       __s8 *ext_err)
{
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state_new = {};
	bool has_l4_header;
	struct lb4_service *svc;
	struct lb4_key key = {};
	__u16 proxy_port = 0;
	__u32 cluster_id = 0;
	int l4_off;
	int ret = 0;

	has_l4_header = ipv4_has_l4_header(ip4);

	ret = lb4_extract_tuple(ctx, ip4, ETH_HLEN, &l4_off, &tuple);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNSUPP_SERVICE_PROTO || ret == DROP_UNKNOWN_L4)
			goto skip_service_lookup;
		else
			return ret;
	}

	lb4_fill_key(&key, &tuple);

	svc = lb4_lookup_service(&key, is_defined(ENABLE_NODEPORT));
	if (svc) {
#if defined(ENABLE_L7_LB)
		if (lb4_svc_is_l7loadbalancer(svc)) {
			proxy_port = (__u16)svc->l7_lb_proxy_port;
			goto skip_service_lookup;
		}
#endif /* ENABLE_L7_LB */
		/* When socket-LB is enabled, local-redirect services are load-balanced in
		 * bpf_sock. In some cases, load-balancing can be skipped for certain local
		 * redirect services based on user configured policies. Per packet LB should
		 * not override LB decisions made for local-redirect services in bpf_sock.
		 */
#if defined(ENABLE_LOCAL_REDIRECT_POLICY) && defined(ENABLE_SOCKET_LB_FULL)
		if (unlikely(lb4_svc_is_localredirect(svc)))
			goto skip_service_lookup;
#endif /* ENABLE_LOCAL_REDIRECT_POLICY && ENABLE_SOCKET_LB_FULL */
		ret = lb4_local(get_ct_map4(&tuple), ctx, ipv4_is_fragment(ip4),
				ETH_HLEN, l4_off, &key, &tuple, svc, &ct_state_new,
				has_l4_header, false, &cluster_id, ext_err, ENDPOINT_NETNS_COOKIE);

#ifdef SERVICE_NO_BACKEND_RESPONSE
		if (ret == DROP_NO_SERVICE)
			ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_NO_SERVICE,
						 ext_err);
#endif

		if (IS_ERR(ret))
			return ret;
	}
skip_service_lookup:
	/* Store state to be picked up on the continuation tail call. */
	lb4_ctx_store_state(ctx, &ct_state_new, proxy_port, cluster_id);
	return tail_call_internal(ctx, CILIUM_CALL_IPV4_CT_EGRESS, ext_err);
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
static __always_inline int __per_packet_lb_svc_xlate_6(void *ctx, struct ipv6hdr *ip6,
						       __s8 *ext_err)
{
	struct ipv6_ct_tuple tuple __align_stack_8 = {};
	struct ct_state ct_state_new = {};
	struct lb6_service *svc;
	struct lb6_key key = {};
	__u16 proxy_port = 0;
	int l4_off;
	int ret = 0;

	ret = lb6_extract_tuple(ctx, ip6, ETH_HLEN, &l4_off, &tuple);
	if (IS_ERR(ret)) {
		if (ret == DROP_UNSUPP_SERVICE_PROTO || ret == DROP_UNKNOWN_L4)
			goto skip_service_lookup;
		else
			return ret;
	}

	lb6_fill_key(&key, &tuple);

	/*
	 * Check if the destination address is among the address that should
	 * be load balanced. This operation is performed before we go through
	 * the connection tracker to allow storing the reverse nat index in
	 * the CT entry for destination endpoints where we can't encode the
	 * state in the address.
	 */
	svc = lb6_lookup_service(&key, is_defined(ENABLE_NODEPORT));
	if (svc) {
#if defined(ENABLE_L7_LB)
		if (lb6_svc_is_l7loadbalancer(svc)) {
			proxy_port = (__u16)svc->l7_lb_proxy_port;
			goto skip_service_lookup;
		}
#endif /* ENABLE_L7_LB */
		/* See comment in __per_packet_lb_svc_xlate_4. */
#if defined(ENABLE_LOCAL_REDIRECT_POLICY) && defined(ENABLE_SOCKET_LB_FULL)
		if (unlikely(lb6_svc_is_localredirect(svc)))
			goto skip_service_lookup;
#endif /* ENABLE_LOCAL_REDIRECT_POLICY && ENABLE_SOCKET_LB_FULL */
		ret = lb6_local(get_ct_map6(&tuple), ctx, ETH_HLEN, l4_off,
				&key, &tuple, svc, &ct_state_new, false, ext_err,
				ENDPOINT_NETNS_COOKIE);

#ifdef SERVICE_NO_BACKEND_RESPONSE
		if (ret == DROP_NO_SERVICE)
			ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_NO_SERVICE,
						 ext_err);
#endif

		if (IS_ERR(ret))
			return ret;
	}

skip_service_lookup:
	/* Store state to be picked up on the continuation tail call. */
	lb6_ctx_store_state(ctx, &ct_state_new, proxy_port);
	return tail_call_internal(ctx, CILIUM_CALL_IPV6_CT_EGRESS, ext_err);
}
#endif /* ENABLE_IPV6 */

#endif

#if defined(ENABLE_ARP_PASSTHROUGH) && defined(ENABLE_ARP_RESPONDER)
#error "Either ENABLE_ARP_PASSTHROUGH or ENABLE_ARP_RESPONDER can be defined"
#endif

#ifdef ENABLE_IPV4
static __always_inline void *
select_ct_map4(struct __ctx_buff *ctx __maybe_unused, int dir __maybe_unused,
	       struct ipv4_ct_tuple *tuple)
{
	__u32 cluster_id = 0;
#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
	if (dir == CT_EGRESS)
		cluster_id = ctx_load_meta(ctx, CB_CLUSTER_ID_EGRESS);
	else if (dir == CT_INGRESS)
		cluster_id = ctx_load_meta(ctx, CB_CLUSTER_ID_INGRESS);
#endif
	return get_cluster_ct_map4(tuple, cluster_id);
}
#endif

#if defined ENABLE_IPV4 || defined ENABLE_IPV6
static __always_inline int drop_for_direction(struct __ctx_buff *ctx,
					      enum ct_dir dir, int reason,
					      __s8 ext_err)
{
	__u32 dst = 0;
	__u32 dst_id = 0;
	enum metric_dir m_dir = METRIC_EGRESS;
	__u32 src_label = 0;
	__u32 sec_label = SECLABEL;

#if defined ENABLE_IPV4 && defined ENABLE_IPV6
	switch (ctx_get_protocol(ctx)) {
	case bpf_htons(ETH_P_IP):
		sec_label = SECLABEL_IPV4;
		break;
	case bpf_htons(ETH_P_IPV6):
		sec_label = SECLABEL_IPV6;
		break;
	}
#endif

	switch (dir) {
	case CT_EGRESS:
		dst_id = 0;
		dst = 0;
		src_label = sec_label;
		m_dir = METRIC_EGRESS;
		break;
	case CT_INGRESS:
		dst = sec_label;
		dst_id = LXC_ID;
		src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
		m_dir = METRIC_INGRESS;
		break;
	/* ingress/egress only for now */
	default:
		__throw_build_bug();
	}

	return send_drop_notify_ext(ctx, src_label, dst, dst_id, reason,
				    ext_err, CTX_ACT_DROP, m_dir);
}
#endif /* ENABLE_IPV4 || ENABLE_IPV6 */

#define TAIL_CT_LOOKUP4(ID, NAME, DIR, CONDITION, TARGET_ID, TARGET_NAME)	\
__section_tail(CILIUM_MAP_CALLS, ID)						\
static __always_inline								\
int NAME(struct __ctx_buff *ctx)						\
{										\
	struct ct_buffer4 ct_buffer = {};					\
	struct ipv4_ct_tuple *tuple;						\
	struct ct_state *ct_state;						\
	void *data, *data_end;							\
	int ret = CTX_ACT_OK;							\
	struct iphdr *ip4;							\
	__s8 ext_err = 0;							\
	__u32 zero = 0;								\
	void *map;								\
										\
	ct_state = (struct ct_state *)&ct_buffer.ct_state;			\
	tuple = (struct ipv4_ct_tuple *)&ct_buffer.tuple;			\
										\
	if (!revalidate_data(ctx, &data, &data_end, &ip4))			\
		return drop_for_direction(ctx, DIR, DROP_INVALID, ext_err);	\
										\
	tuple->nexthdr = ip4->protocol;						\
	tuple->daddr = ip4->daddr;						\
	tuple->saddr = ip4->saddr;						\
	ct_buffer.l4_off = ETH_HLEN + ipv4_hdrlen(ip4);				\
										\
	map = select_ct_map4(ctx, DIR, tuple);					\
	if (!map)								\
		return drop_for_direction(ctx, DIR, DROP_CT_NO_MAP_FOUND,	\
					  ext_err);				\
										\
	ct_buffer.ret = ct_lookup4(map, tuple, ctx, ip4, ct_buffer.l4_off,	\
				   DIR, ct_state, &ct_buffer.monitor);		\
	if (ct_buffer.ret < 0)							\
		return drop_for_direction(ctx, DIR, ct_buffer.ret, ext_err);	\
	if (map_update_elem(&CT_TAIL_CALL_BUFFER4, &zero, &ct_buffer, 0) < 0)	\
		return drop_for_direction(ctx, DIR, DROP_INVALID_TC_BUFFER,	\
					  ext_err);				\
										\
	ret = invoke_tailcall_if(CONDITION, TARGET_ID, TARGET_NAME, &ext_err);	\
	if (IS_ERR(ret))							\
		return drop_for_direction(ctx, DIR, ret, ext_err);		\
										\
	return ret;								\
}

#define TAIL_CT_LOOKUP6(ID, NAME, DIR, CONDITION, TARGET_ID, TARGET_NAME)	\
__section_tail(CILIUM_MAP_CALLS, ID)						\
static __always_inline								\
int NAME(struct __ctx_buff *ctx)						\
{										\
	struct ct_buffer6 ct_buffer = {};					\
	int ret = CTX_ACT_OK, hdrlen;						\
	struct ipv6_ct_tuple *tuple;						\
	struct ct_state *ct_state;						\
	void *data, *data_end;							\
	struct ipv6hdr *ip6;							\
	__s8 ext_err = 0;							\
	__u32 zero = 0;								\
										\
	ct_state = (struct ct_state *)&ct_buffer.ct_state;			\
	tuple = (struct ipv6_ct_tuple *)&ct_buffer.tuple;			\
										\
	if (!revalidate_data(ctx, &data, &data_end, &ip6))			\
		return drop_for_direction(ctx, DIR, DROP_INVALID, ext_err);	\
										\
	tuple->nexthdr = ip6->nexthdr;						\
	ipv6_addr_copy(&tuple->daddr, (union v6addr *)&ip6->daddr);		\
	ipv6_addr_copy(&tuple->saddr, (union v6addr *)&ip6->saddr);		\
										\
	hdrlen = ipv6_hdrlen(ctx, &tuple->nexthdr);				\
	if (hdrlen < 0)								\
		return drop_for_direction(ctx, DIR, hdrlen, ext_err);		\
										\
	ct_buffer.l4_off = ETH_HLEN + hdrlen;					\
										\
	ct_buffer.ret = ct_lookup6(get_ct_map6(tuple), tuple, ctx,		\
				   ct_buffer.l4_off, DIR, ct_state,		\
				   &ct_buffer.monitor);				\
	if (ct_buffer.ret < 0)							\
		return drop_for_direction(ctx, DIR, ct_buffer.ret, ext_err);	\
										\
	if (map_update_elem(&CT_TAIL_CALL_BUFFER6, &zero, &ct_buffer, 0) < 0)	\
		return drop_for_direction(ctx, DIR, DROP_INVALID_TC_BUFFER,	\
					  ext_err);				\
										\
	ret = invoke_tailcall_if(CONDITION, TARGET_ID, TARGET_NAME, &ext_err);	\
	if (IS_ERR(ret))							\
		return drop_for_direction(ctx, DIR, ret, ext_err);		\
										\
	return ret;								\
}

#ifdef ENABLE_CUSTOM_CALLS
/* Encode return value and identity into cb buffer. This is used before
 * executing tail calls to custom programs. "ret" is the return value supposed
 * to be returned to the kernel, needed by the callee to preserve the datapath
 * logics. The "identity" is the security identity of the local endpoint: the
 * source of the packet on ingress path, or its destination on the egress path.
 * We encode it so that custom programs can retrieve it and use it at their
 * convenience.
 */
static __always_inline int
encode_custom_prog_meta(struct __ctx_buff *ctx, int ret, __u32 identity)
{
	__u32 custom_meta = 0;

	/* If we cannot encode return value on 8 bits, return an error so we can
	 * skip the tail call entirely, as custom program has no way to return
	 * expected value and datapath logics will break.
	 */
	if ((ret & 0xff) != ret)
		return -1;
	custom_meta |= (__u32)(ret & 0xff) << 24;
	custom_meta |= (identity & 0xffffff);
	ctx_store_meta(ctx, CB_CUSTOM_CALLS, custom_meta);
	return 0;
}
#endif

#ifdef ENABLE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ct_buffer6);
	__uint(max_entries, 1);
} CT_TAIL_CALL_BUFFER6 __section_maps_btf;

/* Handle egress IPv6 traffic from a container after service translation has been done
 * either at the socket level or by the caller.
 * In the case of the caller doing the service translation it passes in state via CB,
 * which we take in with lb6_ctx_restore_state().
 */
static __always_inline int handle_ipv6_from_lxc(struct __ctx_buff *ctx, __u32 *dst_sec_identity,
						__s8 *ext_err)
{
	struct ct_state *ct_state, ct_state_new = {};
	struct ipv6_ct_tuple *tuple;
#ifdef ENABLE_ROUTING
	union macaddr router_mac = THIS_INTERFACE_MAC;
#endif
	struct ct_buffer6 *ct_buffer;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, verdict, l4_off, zero = 0;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 __maybe_unused tunnel_endpoint = 0;
	__u8 __maybe_unused encrypt_key = 0;
	bool __maybe_unused skip_tunnel = false;
	enum ct_status ct_status;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	__u8 auth_type = 0;
	__u16 proxy_port = 0;
	bool from_l7lb = false;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Determine the destination category for policy fallback.  Service
	 * translation of the destination address is done before this function,
	 * so we can do this first.
	 */
	if (1) {
		const union v6addr *daddr = (union v6addr *)&ip6->daddr;
		struct remote_endpoint_info *info;

		info = lookup_ip6_remote_endpoint(daddr, 0);
		if (info && info->sec_identity) {
			*dst_sec_identity = info->sec_identity;
			tunnel_endpoint = info->tunnel_endpoint;
			encrypt_key = get_min_encrypt_key(info->key);
			skip_tunnel = info->flag_skip_tunnel;
		} else {
			*dst_sec_identity = WORLD_IPV6_ID;
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   daddr->p4, *dst_sec_identity);
	}

#ifdef ENABLE_PER_PACKET_LB
	/* Restore ct_state from per packet lb handling in the previous tail call. */
	lb6_ctx_restore_state(ctx, &ct_state_new, &proxy_port);
	/* No hairpin/loopback support for IPv6, see lb6_local(). */
#endif /* ENABLE_PER_PACKET_LB */

	ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER6, &zero);
	if (!ct_buffer)
		return DROP_INVALID_TC_BUFFER;
	if (ct_buffer->tuple.saddr.d1 == 0 && ct_buffer->tuple.saddr.d2 == 0)
		/* The map value is zeroed so the map update didn't happen somehow. */
		return DROP_INVALID_TC_BUFFER;

	tuple = (struct ipv6_ct_tuple *)&ct_buffer->tuple;
	ct_state = (struct ct_state *)&ct_buffer->ct_state;
	trace.monitor = ct_buffer->monitor;
	ret = ct_buffer->ret;
	ct_status = (enum ct_status)ret;
	trace.reason = (enum trace_reason)ret;
	l4_off = ct_buffer->l4_off;

#if defined(ENABLE_L7_LB)
	if (proxy_port > 0) {
		/* tuple addresses have been swapped by CT lookup */
		cilium_dbg3(ctx, DBG_L7_LB, tuple->daddr.p4, tuple->saddr.p4,
			    bpf_ntohs(proxy_port));
		goto skip_policy_enforcement;
	}
#endif /* ENABLE_L7_LB */

	/* Skip policy enforcement for return traffic. */
	if (ct_status == CT_REPLY || ct_status == CT_RELATED) {
		/* Check if this is return traffic to an ingress proxy. */
		if (ct_state->proxy_redirect) {
			send_trace_notify(ctx, TRACE_TO_PROXY, SECLABEL_IPV6,
					  UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
					  TRACE_IFINDEX_UNKNOWN, trace.reason,
					  trace.monitor);
			/* Stack will do a socket match and deliver locally. */
			return ctx_redirect_to_proxy6(ctx, tuple, 0, false);
		}
		/* proxy_port remains 0 in this case */
		goto skip_policy_enforcement;
	}

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check.
	 */
	verdict = policy_can_egress6(ctx, &POLICY_MAP, tuple, l4_off, SECLABEL_IPV6,
				     *dst_sec_identity, &policy_match_type, &audited,
				     ext_err, &proxy_port);

	if (verdict == DROP_POLICY_AUTH_REQUIRED) {
		auth_type = (__u8)*ext_err;
		verdict = auth_lookup(ctx, SECLABEL_IPV6, *dst_sec_identity, tunnel_endpoint,
				      auth_type);
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ct_status != CT_ESTABLISHED) {
		send_policy_verdict_notify(ctx, *dst_sec_identity, tuple->dport,
					   tuple->nexthdr, POLICY_EGRESS, 1,
					   verdict, proxy_port,
					   policy_match_type, audited,
					   auth_type);
	}

	if (verdict != CTX_ACT_OK)
		return verdict;

skip_policy_enforcement:
#if defined(ENABLE_L7_LB)
	from_l7lb = ctx_load_meta(ctx, CB_FROM_HOST) == FROM_HOST_L7_LB;
#endif
	switch (ct_status) {
	case CT_NEW:
ct_recreate6:
		/* New connection implies that rev_nat_index remains untouched
		 * to the index provided by the loadbalancer (if it applied).
		 * Create a CT entry which allows to track replies and to
		 * reverse NAT.
		 */
		ct_state_new.src_sec_id = SECLABEL_IPV6;
		ct_state_new.proxy_redirect = proxy_port > 0;
		ct_state_new.from_l7lb = from_l7lb;

		ret = ct_create6(get_ct_map6(tuple), &CT_MAP_ANY6, tuple, ctx,
				 CT_EGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
		trace.monitor = TRACE_PAYLOAD_LEN;
		break;

	case CT_ESTABLISHED:
		/* Did we end up at a stale non-service entry? Recreate if so. */
		if (unlikely(ct_state->rev_nat_index != ct_state_new.rev_nat_index))
			goto ct_recreate6;

		/* See comment in handle_ipv4_from_lxc(). */
		ct_state_new.proxy_redirect = proxy_port > 0;
		if (unlikely(ct_state->proxy_redirect != ct_state_new.proxy_redirect))
			goto ct_recreate6;
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(ctx);

#ifdef ENABLE_NODEPORT
		/* See comment in handle_ipv4_from_lxc(). */
		if (ct_state->node_port && lb_is_svc_proto(tuple->nexthdr)) {
			send_trace_notify(ctx, TRACE_TO_NETWORK, SECLABEL_IPV6,
					  *dst_sec_identity, TRACE_EP_ID_UNKNOWN,
					  TRACE_IFINDEX_UNKNOWN,
					  trace.reason, trace.monitor);
			return tail_call_internal(ctx, CILIUM_CALL_IPV6_NODEPORT_REVNAT,
						  ext_err);
		}
#endif /* ENABLE_NODEPORT */
		break;
	default:
		return DROP_UNKNOWN_CT;
	}

#ifdef ENABLE_SRV6
	{
		__u32 *vrf_id;
		union v6addr *sid;

		/* Determine if packet belongs to a VRF */
		vrf_id = srv6_lookup_vrf6(&ip6->saddr, &ip6->daddr);
		if (vrf_id) {
			/* Do policy lookup if it belongs to a VRF */
			sid = srv6_lookup_policy6(*vrf_id, &ip6->daddr);
			if (sid) {
				/* If there's a policy, tailcall to the H.Encaps logic */
				srv6_store_meta_sid(ctx, sid);
				return tail_call_internal(ctx, CILIUM_CALL_SRV6_ENCAP,
							  ext_err);
			}
		}
	}
#endif /* ENABLE_SRV6 */

	/* L7 LB does L7 policy enforcement, so we only redirect packets
	 * NOT from L7 LB.
	 */
	if (!from_l7lb && proxy_port > 0) {
		/* Trace the packet before it is forwarded to proxy */
		send_trace_notify(ctx, TRACE_TO_PROXY, SECLABEL_IPV6, UNKNOWN_ID,
				  bpf_ntohs(proxy_port), TRACE_IFINDEX_UNKNOWN,
				  trace.reason, trace.monitor);
		return ctx_redirect_to_proxy6(ctx, tuple, proxy_port, false);
	}

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)
	/* If the destination is the local host and per-endpoint routes are
	 * enabled, jump to the bpf_host program to enforce ingress host policies.
	 */
	if (*dst_sec_identity == HOST_ID) {
		ctx_store_meta(ctx, CB_FROM_HOST, 0);
		ret = tail_call_policy(ctx, HOST_EP_ID);

		/* return fine-grained error: */
		return DROP_HOST_NOT_READY;
	}
#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */

	if (is_defined(ENABLE_ROUTING) || is_defined(ENABLE_HOST_ROUTING)) {
		struct endpoint_info *ep;

		/* Lookup IPv6 address, this will return a match if:
		 *  - The destination IP address belongs to a local endpoint managed by
		 *    cilium
		 *  - The destination IP address is an IP address associated with the
		 *    host itself.
		 */
		ep = lookup_ip6_endpoint(ip6);
		if (ep) {
#if defined(ENABLE_HOST_ROUTING) || defined(ENABLE_ROUTING)
			if (ep->flags & ENDPOINT_F_HOST) {
				if (is_defined(ENABLE_ROUTING)) {
# ifdef HOST_IFINDEX
					goto to_host;
# endif
					return DROP_HOST_UNREACHABLE;
				}
				goto pass_to_stack;
			}
#endif /* ENABLE_HOST_ROUTING || ENABLE_ROUTING */
			policy_clear_mark(ctx);
			/* If the packet is from L7 LB it is coming from the host */
			return ipv6_local_delivery(ctx, ETH_HLEN, SECLABEL_IPV6,
						   MARK_MAGIC_IDENTITY, ep,
						   METRIC_EGRESS, from_l7lb, false);
		}
	}

	/* The packet goes to a peer not managed by this agent instance */
#ifdef TUNNEL_MODE
	if (!skip_tunnel) {
		struct tunnel_key key = {};
		union v6addr *daddr = (union v6addr *)&ip6->daddr;

		/* Lookup the destination prefix in the list of known
		 * destination prefixes. If there is a match, the packet will
		 * be encapsulated to that node and then routed by the agent on
		 * the remote node.
		 *
		 * IPv6 lookup key: daddr/96
		 */
		ipv6_addr_copy(&key.ip6, daddr);
		key.ip6.p4 = 0;
		key.family = ENDPOINT_KEY_IPV6;

#if !defined(ENABLE_NODEPORT) && defined(ENABLE_HOST_FIREWALL)
		/* See comment in handle_ipv4_from_lxc(). */
		if ((ct_status == CT_REPLY || ct_status == CT_RELATED) &&
		    identity_is_remote_node(*dst_sec_identity))
			goto encrypt_to_stack;
#endif /* !ENABLE_NODEPORT && ENABLE_HOST_FIREWALL */

		/* Three cases exist here either (a) the encap and redirect could
		 * not find the tunnel so fallthrough to nat46 and stack, (b)
		 * the packet needs IPSec encap so push ctx to stack for encap, or
		 * (c) packet was redirected to tunnel device so return.
		 */
		ret = encap_and_redirect_lxc(ctx, tunnel_endpoint, 0, 0, encrypt_key,
					     &key, SECLABEL_IPV6, *dst_sec_identity,
					     &trace);
		if (ret == CTX_ACT_OK)
			goto encrypt_to_stack;
		else if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif
	if (is_defined(ENABLE_HOST_ROUTING)) {
		int oif = 0;

		ret = fib_redirect_v6(ctx, ETH_HLEN, ip6, false, false, ext_err, &oif);
		if (fib_ok(ret))
			send_trace_notify(ctx, TRACE_TO_NETWORK, SECLABEL_IPV6,
					  *dst_sec_identity, TRACE_EP_ID_UNKNOWN, oif,
					  trace.reason, trace.monitor);
		return ret;
	}

	goto pass_to_stack;

#if defined(ENABLE_HOST_ROUTING) || defined(ENABLE_ROUTING)
to_host:
#endif
#ifdef ENABLE_ROUTING
	if (is_defined(ENABLE_HOST_FIREWALL) && *dst_sec_identity == HOST_ID) {
		send_trace_notify(ctx, TRACE_TO_HOST, SECLABEL_IPV6, HOST_ID,
				  TRACE_EP_ID_UNKNOWN,
				  HOST_IFINDEX, trace.reason, trace.monitor);
		return ctx_redirect(ctx, HOST_IFINDEX, BPF_F_INGRESS);
	}
#endif

pass_to_stack:
#ifdef ENABLE_ROUTING
	ret = ipv6_l3(ctx, ETH_HLEN, NULL, (__u8 *)&router_mac.addr, METRIC_EGRESS);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
#endif

#ifndef TUNNEL_MODE
# ifdef ENABLE_IPSEC
	if (encrypt_key && tunnel_endpoint) {
		ret = set_ipsec_encrypt(ctx, encrypt_key, tunnel_endpoint,
					SECLABEL_IPV6, false, false);
		if (unlikely(ret != CTX_ACT_OK))
			return ret;
	} else
# endif /* ENABLE_IPSEC */
#endif /* TUNNEL_MODE */
	{
#ifdef ENABLE_IDENTITY_MARK
		/* Always encode the source identity when passing to the stack.
		 * If the stack hairpins the packet back to a local endpoint the
		 * source identity can still be derived even if SNAT is
		 * performed by a component such as portmap.
		 */
		set_identity_mark(ctx, SECLABEL_IPV6, MARK_MAGIC_IDENTITY);
#endif
	}

#ifdef TUNNEL_MODE
encrypt_to_stack:
#endif
	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL_IPV6, *dst_sec_identity,
			  TRACE_EP_ID_UNKNOWN,
			  TRACE_IFINDEX_UNKNOWN, trace.reason, trace.monitor);

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, 0);

	return CTX_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_LXC_CONT)
static __always_inline
int tail_handle_ipv6_cont(struct __ctx_buff *ctx)
{
	__u32 dst_sec_identity = 0;
	__s8 ext_err = 0;
	int ret = handle_ipv6_from_lxc(ctx, &dst_sec_identity, &ext_err);

	if (IS_ERR(ret))
		return send_drop_notify_ext(ctx, SECLABEL_IPV6, dst_sec_identity,
					    TRACE_EP_ID_UNKNOWN, ret, ext_err,
					    CTX_ACT_DROP, METRIC_EGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	if (!encode_custom_prog_meta(ctx, ret, dst_sec_identity)) {
		tail_call_static(ctx, CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV6_EGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

TAIL_CT_LOOKUP6(CILIUM_CALL_IPV6_CT_EGRESS, tail_ipv6_ct_egress, CT_EGRESS,
		is_defined(ENABLE_PER_PACKET_LB),
		CILIUM_CALL_IPV6_FROM_LXC_CONT, tail_handle_ipv6_cont)

static __always_inline int __tail_handle_ipv6(struct __ctx_buff *ctx,
					      __s8 *ext_err __maybe_unused)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Handle special ICMPv6 NDP messages, and all remaining packets
	 * are subjected to forwarding into the container.
	 */
	if (unlikely(is_icmp6_ndp(ctx, ip6, ETH_HLEN)))
		return icmp6_ndp_handle(ctx, ETH_HLEN, METRIC_EGRESS, ext_err);

	if (unlikely(!is_valid_lxc_src_ip(ip6)))
		return DROP_INVALID_SIP;

#ifdef ENABLE_PER_PACKET_LB
	/* will tailcall internally or return error */
	return __per_packet_lb_svc_xlate_6(ctx, ip6, ext_err);
#else
	/* won't be a tailcall, see TAIL_CT_LOOKUP6 */
	return tail_ipv6_ct_egress(ctx);
#endif /* ENABLE_PER_PACKET_LB */
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_LXC)
int tail_handle_ipv6(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;
	int ret = __tail_handle_ipv6(ctx, &ext_err);

	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, SECLABEL_IPV6, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);
	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ct_buffer4);
	__uint(max_entries, 1);
} CT_TAIL_CALL_BUFFER4 __section_maps_btf;

/* Handle egress IPv4 traffic from a container after service translation has been done
 * either at the socket level or by the caller.
 * In the case of the caller doing the service translation it passes in state via CB,
 * which we take in with lb4_ctx_restore_state().
 */
static __always_inline int handle_ipv4_from_lxc(struct __ctx_buff *ctx, __u32 *dst_sec_identity,
						__s8 *ext_err)
{
	struct ct_state *ct_state, ct_state_new = {};
	struct ipv4_ct_tuple *tuple;
#ifdef ENABLE_ROUTING
	union macaddr router_mac = THIS_INTERFACE_MAC;
#endif
	void *data, *data_end;
	struct iphdr *ip4;
	int ret, verdict, l4_off;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 __maybe_unused tunnel_endpoint = 0, zero = 0;
	__u8 __maybe_unused encrypt_key = 0;
	bool __maybe_unused skip_tunnel = false;
	bool hairpin_flow = false; /* endpoint wants to access itself via service IP */
	__u8 policy_match_type = POLICY_MATCH_NONE;
	struct ct_buffer4 *ct_buffer;
	__u8 audited = 0;
	__u8 auth_type = 0;
	enum ct_status ct_status;
	__u16 proxy_port = 0;
	bool from_l7lb = false;
	__u32 cluster_id = 0;
	void *ct_map, *ct_related_map = NULL;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

#ifdef ENABLE_PER_PACKET_LB
	/* Restore ct_state from per packet lb handling in the previous tail call. */
	lb4_ctx_restore_state(ctx, &ct_state_new, &proxy_port, &cluster_id);
	hairpin_flow = ct_state_new.loopback;
#endif /* ENABLE_PER_PACKET_LB */

	/* Determine the destination category for policy fallback. */
	if (1) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(ip4->daddr, cluster_id);
		if (info && info->sec_identity) {
			*dst_sec_identity = info->sec_identity;
			tunnel_endpoint = info->tunnel_endpoint;
			encrypt_key = get_min_encrypt_key(info->key);
			skip_tunnel = info->flag_skip_tunnel;
		} else {
			*dst_sec_identity = WORLD_IPV4_ID;
		}

		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->daddr, *dst_sec_identity);
	}

	ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER4, &zero);
	if (!ct_buffer)
		return DROP_INVALID_TC_BUFFER;
	if (ct_buffer->tuple.saddr == 0)
		/* The map value is zeroed so the map update didn't happen somehow. */
		return DROP_INVALID_TC_BUFFER;

	tuple = (struct ipv4_ct_tuple *)&ct_buffer->tuple;
	ct_state = (struct ct_state *)&ct_buffer->ct_state;
	trace.monitor = ct_buffer->monitor;
	ret = ct_buffer->ret;
	ct_status = (enum ct_status)ret;
	trace.reason = (enum trace_reason)ret;
	l4_off = ct_buffer->l4_off;

#if defined(ENABLE_L7_LB)
	if (proxy_port > 0) {
		/* tuple addresses have been swapped by CT lookup */
		cilium_dbg3(ctx, DBG_L7_LB, tuple->daddr, tuple->saddr, bpf_ntohs(proxy_port));
		goto skip_policy_enforcement;
	}
#endif /* ENABLE_L7_LB */

	/* Skip policy enforcement for return traffic. */
	if (ct_status == CT_REPLY || ct_status == CT_RELATED) {
		/* Check if this is return traffic to an ingress proxy. */
		if (ct_state->proxy_redirect) {
			send_trace_notify(ctx, TRACE_TO_PROXY, SECLABEL_IPV4,
					  UNKNOWN_ID, TRACE_EP_ID_UNKNOWN,
					  TRACE_IFINDEX_UNKNOWN, trace.reason,
					  trace.monitor);
			/* Stack will do a socket match and deliver locally. */
			return ctx_redirect_to_proxy4(ctx, tuple, 0, false);
		}
		/* proxy_port remains 0 in this case */
		goto skip_policy_enforcement;
	}

	/* When an endpoint connects to itself via service clusterIP, we need
	 * to skip the policy enforcement. If we didn't, the user would have to
	 * define policy rules to allow pods to talk to themselves. We still
	 * want to execute the conntrack logic so that replies can be correctly
	 * matched.
	 */
	if (hairpin_flow)
		goto skip_policy_enforcement;

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check.
	 */
	verdict = policy_can_egress4(ctx, &POLICY_MAP, tuple, l4_off, SECLABEL_IPV4,
				     *dst_sec_identity, &policy_match_type, &audited,
				     ext_err, &proxy_port);

	if (verdict == DROP_POLICY_AUTH_REQUIRED) {
		auth_type = (__u8)*ext_err;
		verdict = auth_lookup(ctx, SECLABEL_IPV4, *dst_sec_identity, tunnel_endpoint,
				      auth_type);
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ct_status != CT_ESTABLISHED) {
		send_policy_verdict_notify(ctx, *dst_sec_identity, tuple->dport,
					   tuple->nexthdr, POLICY_EGRESS, 0,
					   verdict, proxy_port,
					   policy_match_type, audited,
					   auth_type);
	}

	if (verdict != CTX_ACT_OK)
		return verdict;

skip_policy_enforcement:
#if defined(ENABLE_L7_LB)
	from_l7lb = ctx_load_meta(ctx, CB_FROM_HOST) == FROM_HOST_L7_LB;
#endif
	switch (ct_status) {
	case CT_NEW:
ct_recreate4:
		/* New connection implies that rev_nat_index remains untouched
		 * to the index provided by the loadbalancer (if it applied).
		 * Create a CT entry which allows to track replies and to
		 * reverse NAT.
		 */
		ct_state_new.src_sec_id = SECLABEL_IPV4;

		ct_map = get_cluster_ct_map4(tuple, cluster_id);
		if (!ct_map)
			return DROP_CT_NO_MAP_FOUND;

		ct_related_map = get_cluster_ct_any_map4(cluster_id);
		if (!ct_related_map)
			return DROP_CT_NO_MAP_FOUND;

		/* We could avoid creating related entries for legacy ClusterIP
		 * handling here, but turns out that verifier cannot handle it.
		 */
		ct_state_new.proxy_redirect = proxy_port > 0;
		ct_state_new.from_l7lb = from_l7lb;

		ret = ct_create4(ct_map, ct_related_map, tuple, ctx,
				 CT_EGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
		break;

	case CT_ESTABLISHED:
		/* Did we end up at a stale non-service entry? Recreate if so. */
		if (unlikely(ct_state->rev_nat_index != ct_state_new.rev_nat_index))
			goto ct_recreate4;

		/* Recreate the CT entry if the proxy_redirect flag is stale.
		 * Otherwise, the return packet will be erroneously redirected (or not)
		 * This check assumes the case where non-TCP packets hit the stale
		 * CT entry with the proxy_redirect flag, or active TCP connection
		 * suddenly comes into the scope of an L7 policy. Recreating the entry
		 * updates the proxy_redirect flag properly.
		 *
		 * if the packet hits a closing stale entry, ct_lookup returns CT_NEW and
		 * caller recreates the entry.
		 */
		ct_state_new.proxy_redirect = proxy_port > 0;
		if (unlikely(ct_state->proxy_redirect != ct_state_new.proxy_redirect))
			goto ct_recreate4;
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(ctx);

#ifdef ENABLE_NODEPORT
		/* This handles reply traffic for the case where the nodeport EP
		 * is local to the node. We'll do the tail call to perform
		 * the reverse DNAT.
		 *
		 * This codepath currently doesn't support revDNAT for ICMP,
		 * so make sure that we only send TCP/UDP/SCTP down this way.
		 */
		if (ct_state->node_port && lb_is_svc_proto(tuple->nexthdr)) {
			send_trace_notify(ctx, TRACE_TO_NETWORK, SECLABEL_IPV4,
					  *dst_sec_identity, TRACE_EP_ID_UNKNOWN,
					  TRACE_IFINDEX_UNKNOWN,
					  trace.reason, trace.monitor);
			return tail_call_internal(ctx, CILIUM_CALL_IPV4_NODEPORT_REVNAT,
						  ext_err);
		}
#endif /* ENABLE_NODEPORT */

		break;
	default:
		return DROP_UNKNOWN_CT;
	}

#ifdef ENABLE_SRV6
	{
		__u32 *vrf_id;
		union v6addr *sid;

		/* Determine if packet belongs to a VRF */
		vrf_id = srv6_lookup_vrf4(ip4->saddr, ip4->daddr);
		if (vrf_id) {
			/* Do policy lookup if it belongs to a VRF */
			sid = srv6_lookup_policy4(*vrf_id, ip4->daddr);
			if (sid) {
				/* If there's a policy, tailcall to the H.Encaps logic */
				srv6_store_meta_sid(ctx, sid);
				return tail_call_internal(ctx, CILIUM_CALL_SRV6_ENCAP,
							  ext_err);
			}
		}
	}
#endif /* ENABLE_SRV6 */

	hairpin_flow |= ct_state->loopback;

	/* L7 LB does L7 policy enforcement, so we only redirect packets
	 * NOT from L7 LB.
	 */
	if (!from_l7lb && proxy_port > 0) {
		/* Trace the packet before it is forwarded to proxy */
		send_trace_notify(ctx, TRACE_TO_PROXY, SECLABEL_IPV4, UNKNOWN_ID,
				  bpf_ntohs(proxy_port), TRACE_IFINDEX_UNKNOWN,
				  trace.reason, trace.monitor);
		return ctx_redirect_to_proxy4(ctx, tuple, proxy_port, false);
	}

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)
	/* If the destination is the local host and per-endpoint routes are
	 * enabled, jump to the bpf_host program to enforce ingress host policies.
	 * Note that bpf_lxc can be loaded before bpf_host, so bpf_host's policy
	 * program may not yet be present at this time.
	 */
	if (*dst_sec_identity == HOST_ID) {
		ctx_store_meta(ctx, CB_FROM_HOST, 0);
		ret = tail_call_policy(ctx, HOST_EP_ID);

		/* report fine-grained error: */
		return DROP_HOST_NOT_READY;
	}
#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */

	/* Allow a hairpin packet to be redirected even if ENABLE_ROUTING is
	 * disabled (for example, with per-endpoint routes). Otherwise, the
	 * packet will be dropped by the kernel if the packet will be routed to
	 * the interface it came from after the packet has been passed to the
	 * stack.
	 *
	 * If ENABLE_ROUTING is disabled, but the fast redirect is enabled, we
	 * do lookup the local endpoint here to check whether we must pass the
	 * packet up the stack for the host itself. We also want to run through
	 * the ipv4_local_delivery() function to enforce ingress policies for
	 * that endpoint.
	 */
	if (is_defined(ENABLE_ROUTING) || hairpin_flow ||
	    is_defined(ENABLE_HOST_ROUTING)) {
		__be32 daddr = ip4->daddr;
		struct endpoint_info *ep;

		/* Loopback replies are addressed to IPV4_LOOPBACK, so
		 * an endpoint lookup with ip4->daddr won't work.
		 *
		 * But as it is loopback traffic, the clientIP and backendIP
		 * are identical and we can just use the packet's saddr
		 * for the destination endpoint lookup.
		 */
		if (ct_status == CT_REPLY && hairpin_flow)
			daddr = ip4->saddr;

		/* Lookup IPv4 address, this will return a match if:
		 *  - The destination IP address belongs to a local endpoint
		 *    managed by cilium
		 *  - The destination IP address is an IP address associated with the
		 *    host itself
		 *  - The destination IP address belongs to endpoint itself.
		 */
		ep = __lookup_ip4_endpoint(daddr);
		if (ep) {
#if defined(ENABLE_HOST_ROUTING) || defined(ENABLE_ROUTING)
			if (ep->flags & ENDPOINT_F_HOST) {
				if (is_defined(ENABLE_ROUTING)) {
# ifdef HOST_IFINDEX
					goto to_host;
# endif
					return DROP_HOST_UNREACHABLE;
				}
				goto pass_to_stack;
			}
#endif /* ENABLE_HOST_ROUTING || ENABLE_ROUTING */
			policy_clear_mark(ctx);
			/* If the packet is from L7 LB it is coming from the host */
			return ipv4_local_delivery(ctx, ETH_HLEN, SECLABEL_IPV4,
						   MARK_MAGIC_IDENTITY, ip4,
						   ep, METRIC_EGRESS, from_l7lb,
						   false, 0);
		}
	}

#ifdef ENABLE_EGRESS_GATEWAY_COMMON
	/* We handle traffic to Egress GW that is not redirected to L7 proxy here.
	 * The traffic that has been redirected is processed by to-netdev@bpf_host.
	 * This code is retained in v1.16 to prevent disruptions during the upgrade.
	 * It will be removed in v1.17.
	 */
	ret = egress_gw_handle_packet(ctx, tuple, ct_status, SECLABEL_IPV4,
				      *dst_sec_identity, &trace);
	if (ret != CTX_ACT_OK)
		return ret;
#endif

	/* L7 proxy result in VTEP redirection in bpf_host, but when L7 proxy disabled
	 * We want VTEP redirection handled earlier here to avoid packets passing to
	 * stack to bpf_host for VTEP redirection. When L7 proxy enabled, but no
	 * L7 policy applied to pod, VTEP redirection also happen here.
	 */
#if defined(ENABLE_VTEP)
	{
		struct vtep_key vkey = {};
		struct vtep_value *vtep;

		vkey.vtep_ip = ip4->daddr & VTEP_MASK;
		vtep = map_lookup_elem(&VTEP_MAP, &vkey);
		if (!vtep)
			goto skip_vtep;

		if (vtep->vtep_mac && vtep->tunnel_endpoint) {
			if (eth_store_daddr(ctx, (__u8 *)&vtep->vtep_mac, 0) < 0)
				return DROP_WRITE_ERROR;
			return __encap_and_redirect_with_nodeid(ctx, 0, vtep->tunnel_endpoint,
								SECLABEL_IPV4, WORLD_IPV4_ID,
								WORLD_IPV4_ID, &trace);
		}
	}
skip_vtep:
#endif

#if defined(TUNNEL_MODE) || defined(ENABLE_HIGH_SCALE_IPCACHE)
	if (!skip_tunnel) {
		struct tunnel_key key = {};

		if (cluster_id > UINT16_MAX)
			return DROP_INVALID_CLUSTER_ID;

		key.ip4 = ip4->daddr & IPV4_MASK;
		key.family = ENDPOINT_KEY_IPV4;
		key.cluster_id = (__u16)cluster_id;

#if !defined(ENABLE_NODEPORT) && defined(ENABLE_HOST_FIREWALL)
		/*
		 * For the host firewall, traffic from a pod to a remote node is sent
		 * through the tunnel. In the case of node to remote pod traffic via
		 * externalTrafficPolicy=Local services, packets may be DNATed when
		 * they enter the remote node (without being SNATed at the same time).
		 * If kube-proxy is used, the response needs to go through the stack
		 * to apply the correct reverse DNAT, and then be routed accordingly.
		 * See #14674 for details.
		 */
		if ((ct_status == CT_REPLY || ct_status == CT_RELATED) &&
		    identity_is_remote_node(*dst_sec_identity))
			goto encrypt_to_stack;
#endif /* !ENABLE_NODEPORT && ENABLE_HOST_FIREWALL */

#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
		/*
		 * The destination is remote node, but the connection is originated from tunnel.
		 * Maybe the remote cluster performed SNAT for the inter-cluster communication
		 * and this is the reply for that. In that case, we need to send it back to tunnel.
		 */
		if (ct_status == CT_REPLY) {
			if (identity_is_remote_node(*dst_sec_identity) && ct_state->from_tunnel)
				tunnel_endpoint = ip4->daddr;
		}
#endif

		ret = encap_and_redirect_lxc(ctx, tunnel_endpoint, ip4->saddr,
					     ip4->daddr, encrypt_key, &key,
					     SECLABEL_IPV4, *dst_sec_identity, &trace);
		if (ret == DROP_NO_TUNNEL_ENDPOINT)
			goto pass_to_stack;
		/* If not redirected noteably due to IPSEC then pass up to stack
		 * for further processing.
		 */
		else if (ret == CTX_ACT_OK)
			goto encrypt_to_stack;
#ifdef ENABLE_CLUSTER_AWARE_ADDRESSING
		/* When we redirect, put cluster_id into mark */
		else if (ret == CTX_ACT_REDIRECT) {
			ctx_set_cluster_id_mark(ctx, cluster_id);
			return ret;
		}
#endif
		/* This is either redirect by encap code or an error has
		 * occurred either way return and stack will consume ctx.
		 */
		else
			return ret;
	}
#endif /* TUNNEL_MODE || ENABLE_HIGH_SCALE_IPCACHE */
	if (is_defined(ENABLE_HOST_ROUTING)) {
		int oif = 0;

		ret = fib_redirect_v4(ctx, ETH_HLEN, ip4, false, false, ext_err, &oif);
		if (fib_ok(ret))
			send_trace_notify(ctx, TRACE_TO_NETWORK, SECLABEL_IPV4,
					  *dst_sec_identity, TRACE_EP_ID_UNKNOWN, oif,
					  trace.reason, trace.monitor);
		return ret;
	}

	goto pass_to_stack;

#if defined(ENABLE_HOST_ROUTING) || defined(ENABLE_ROUTING)
to_host:
#endif
#ifdef ENABLE_ROUTING
	if (is_defined(ENABLE_HOST_FIREWALL) && *dst_sec_identity == HOST_ID) {
		send_trace_notify(ctx, TRACE_TO_HOST, SECLABEL_IPV4, HOST_ID,
				  TRACE_EP_ID_UNKNOWN,
				  HOST_IFINDEX, trace.reason, trace.monitor);
		return ctx_redirect(ctx, HOST_IFINDEX, BPF_F_INGRESS);
	}
#endif

pass_to_stack:
#ifdef ENABLE_ROUTING
	ret = ipv4_l3(ctx, ETH_HLEN, NULL, (__u8 *)&router_mac.addr, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
#endif

#ifndef TUNNEL_MODE
# ifdef ENABLE_IPSEC
	if (encrypt_key && tunnel_endpoint) {
		ret = set_ipsec_encrypt(ctx, encrypt_key, tunnel_endpoint,
					SECLABEL_IPV4, false, false);
		if (unlikely(ret != CTX_ACT_OK))
			return ret;
	} else
# endif /* ENABLE_IPSEC */
#endif /* TUNNEL_MODE */
	{
#ifdef ENABLE_IDENTITY_MARK
		/* Always encode the source identity when passing to the stack.
		 * If the stack hairpins the packet back to a local endpoint the
		 * source identity can still be derived even if SNAT is
		 * performed by a component such as portmap.
		 */
		set_identity_mark(ctx, SECLABEL_IPV4, MARK_MAGIC_IDENTITY);
#endif
	}

#if defined(TUNNEL_MODE) || defined(ENABLE_HIGH_SCALE_IPCACHE)
encrypt_to_stack:
#endif
	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL_IPV4, *dst_sec_identity,
			  TRACE_EP_ID_UNKNOWN,
			  TRACE_IFINDEX_UNKNOWN, trace.reason, trace.monitor);
	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, 0);
	return CTX_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_LXC_CONT)
static __always_inline
int tail_handle_ipv4_cont(struct __ctx_buff *ctx)
{
	__u32 dst_sec_identity = 0;
	__s8 ext_err = 0;

	int ret = handle_ipv4_from_lxc(ctx, &dst_sec_identity, &ext_err);

	if (IS_ERR(ret))
		return send_drop_notify_ext(ctx, SECLABEL_IPV4, dst_sec_identity,
					    TRACE_EP_ID_UNKNOWN, ret, ext_err,
					    CTX_ACT_DROP, METRIC_EGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	if (!encode_custom_prog_meta(ctx, ret, dst_sec_identity)) {
		tail_call_static(ctx, CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV4_EGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

TAIL_CT_LOOKUP4(CILIUM_CALL_IPV4_CT_EGRESS, tail_ipv4_ct_egress, CT_EGRESS,
		is_defined(ENABLE_PER_PACKET_LB),
		CILIUM_CALL_IPV4_FROM_LXC_CONT, tail_handle_ipv4_cont)

static __always_inline int __tail_handle_ipv4(struct __ctx_buff *ctx,
					      __s8 *ext_err __maybe_unused)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

/* If IPv4 fragmentation is disabled
 * AND a IPv4 fragmented packet is received,
 * then drop the packet.
 */
#ifndef ENABLE_IPV4_FRAGMENTS
	if (ipv4_is_fragment(ip4))
		return DROP_FRAG_NOSUPPORT;
#endif

	if (unlikely(!is_valid_lxc_src_ipv4(ip4)))
		return DROP_INVALID_SIP;

#ifdef ENABLE_MULTICAST
	if (mcast_ipv4_is_igmp(ip4)) {
		/* note:
		 * we will always drop IGMP from this point on as we have no
		 * need to forward to the stack
		 */
		return mcast_ipv4_handle_igmp(ctx, ip4, data, data_end);
	}

	if (IN_MULTICAST(bpf_ntohl(ip4->daddr))) {
		if (mcast_lookup_subscriber_map(&ip4->daddr))
			return tail_call_internal(ctx,
						  CILIUM_CALL_MULTICAST_EP_DELIVERY,
						  ext_err);
	}
#endif /* ENABLE_MULTICAST */

#ifdef ENABLE_PER_PACKET_LB
	/* will tailcall internally or return error */
	return __per_packet_lb_svc_xlate_4(ctx, ip4, ext_err);
#else
	/* won't be a tailcall, see TAIL_CT_LOOKUP4 */
	return tail_ipv4_ct_egress(ctx);
#endif /* ENABLE_PER_PACKET_LB */
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_LXC)
int tail_handle_ipv4(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;
	int ret = __tail_handle_ipv4(ctx, &ext_err);

	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, SECLABEL_IPV4, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);
	return ret;
}

#ifdef ENABLE_ARP_RESPONDER
/*
 * ARP responder for ARP requests from container
 * Respond to IPV4_GATEWAY with THIS_INTERFACE_MAC
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_ARP)
int tail_handle_arp(struct __ctx_buff *ctx)
{
	union macaddr mac = THIS_INTERFACE_MAC;
	union macaddr smac;
	__be32 sip;
	__be32 tip;

	/* Pass any unknown ARP requests to the Linux stack */
	if (!arp_validate(ctx, &mac, &smac, &sip, &tip))
		return CTX_ACT_OK;

	/*
	 * The endpoint is expected to make ARP requests for its gateway IP.
	 * Most of the time, the gateway IP configured on the endpoint is
	 * IPV4_GATEWAY but it may not be the case if after cilium agent reload
	 * a different gateway is chosen. In such a case, existing endpoints
	 * will have an old gateway configured. Since we don't know the IP of
	 * previous gateways, we answer requests for all IPs with the exception
	 * of the LXC IP (to avoid specific problems, like IP duplicate address
	 * detection checks that might run within the container).
	 */
	if (tip == LXC_IPV4)
		return CTX_ACT_OK;

	return arp_respond(ctx, &mac, tip, &smac, sip, 0);
}
#endif /* ENABLE_ARP_RESPONDER */
#endif /* ENABLE_IPV4 */

/* Attachment/entry point is ingress for veth.
 * It corresponds to packets leaving the container.
 */
__section_entry
int cil_from_container(struct __ctx_buff *ctx)
{
	__u16 proto;
	__u32 sec_label = SECLABEL;
	__s8 ext_err = 0;
	int ret;

	bpf_clear_meta(ctx);
	reset_queue_mapping(ctx);

	send_trace_notify(ctx, TRACE_FROM_LXC, sec_label, UNKNOWN_ID,
			  TRACE_EP_ID_UNKNOWN, TRACE_IFINDEX_UNKNOWN,
			  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		edt_set_aggregate(ctx, LXC_ID);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_FROM_LXC, &ext_err);
		sec_label = SECLABEL_IPV6;
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		edt_set_aggregate(ctx, LXC_ID);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_LXC, &ext_err);
		sec_label = SECLABEL_IPV4;
		break;
#ifdef ENABLE_ARP_PASSTHROUGH
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
#elif defined(ENABLE_ARP_RESPONDER)
	case bpf_htons(ETH_P_ARP):
		ret = tail_call_internal(ctx, CILIUM_CALL_ARP, &ext_err);
		break;
#endif /* ENABLE_ARP_RESPONDER */
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify_ext(ctx, sec_label, UNKNOWN_ID,
					    TRACE_EP_ID_UNKNOWN, ret, ext_err,
					    CTX_ACT_DROP, METRIC_EGRESS);
	return ret;
}

#ifdef ENABLE_IPV6
static __always_inline int
ipv6_policy(struct __ctx_buff *ctx, struct ipv6hdr *ip6, int ifindex, __u32 src_label,
	    struct ipv6_ct_tuple *tuple_out, __s8 *ext_err, __u16 *proxy_port,
	    bool from_tunnel)
{
	struct ct_state *ct_state, ct_state_new = {};
	struct ipv6_ct_tuple *tuple;
	int ret, verdict, l4_off, zero = 0;
	struct ct_buffer6 *ct_buffer;
	bool skip_ingress_proxy = false;
	struct trace_ctx trace;
	union v6addr orig_sip;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	__u8 auth_type = 0;

	policy_clear_mark(ctx);

	ipv6_addr_copy(&orig_sip, (union v6addr *)&ip6->saddr);

	/* If packet is coming from the ingress proxy we have to skip
	 * redirection to the ingress proxy as we would loop forever.
	 */
	skip_ingress_proxy = tc_index_from_ingress_proxy(ctx);

	ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER6, &zero);
	if (!ct_buffer)
		return DROP_INVALID_TC_BUFFER;
	if (ct_buffer->tuple.saddr.d1 == 0 && ct_buffer->tuple.saddr.d2 == 0)
		/* The map value is zeroed so the map update didn't happen somehow. */
		return DROP_INVALID_TC_BUFFER;

	tuple = (struct ipv6_ct_tuple *)&ct_buffer->tuple;
	ct_state = (struct ct_state *)&ct_buffer->ct_state;
	trace.monitor = ct_buffer->monitor;
	trace.reason = (enum trace_reason)ct_buffer->ret;
	ret = ct_buffer->ret;
	l4_off = ct_buffer->l4_off;

	/* Skip policy enforcement for return traffic. */
	if (ret == CT_REPLY || ret == CT_RELATED) {
		/* Check it this is return traffic to an egress proxy.
		 * Do not redirect again if the packet is coming from the egress proxy.
		 * Always redirect connections that originated from L7 LB.
		 */
		if (ct_state_is_from_l7lb(ct_state) ||
		    (ct_state->proxy_redirect && !tc_index_from_egress_proxy(ctx))) {
			/* This is a reply, the proxy port does not need to be embedded
			 * into ctx->mark and *proxy_port can be left unset.
			 */
			send_trace_notify6(ctx, TRACE_TO_PROXY, src_label, SECLABEL_IPV6, &orig_sip,
					   TRACE_EP_ID_UNKNOWN, ifindex, trace.reason,
					   trace.monitor);
			if (tuple_out)
				memcpy(tuple_out, tuple, sizeof(*tuple));
			return POLICY_ACT_PROXY_REDIRECT;
		}

		/* Reverse NAT applies to return traffic only. */
		if (unlikely(ct_state->rev_nat_index)) {
			int ret2;

			ret2 = lb6_rev_nat(ctx, l4_off,
					   ct_state->rev_nat_index, tuple);
			if (IS_ERR(ret2))
				return ret2;
		}

		/* proxy_port remains 0 in this case */
		goto skip_policy_enforcement;
	}

	if (skip_ingress_proxy)
		goto skip_policy_enforcement;

	verdict = policy_can_ingress6(ctx, &POLICY_MAP, tuple, l4_off, src_label,
				      SECLABEL_IPV6, &policy_match_type, &audited,
				      ext_err, proxy_port);
	if (verdict == DROP_POLICY_AUTH_REQUIRED) {
		struct remote_endpoint_info *sep = lookup_ip6_remote_endpoint(&orig_sip, 0);

		if (sep) {
			auth_type = (__u8)*ext_err;
			verdict = auth_lookup(ctx, SECLABEL_IPV6, src_label,
					      sep->tunnel_endpoint, auth_type);
		}
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ret != CT_ESTABLISHED)
		send_policy_verdict_notify(ctx, src_label, tuple->dport,
					   tuple->nexthdr, POLICY_INGRESS, 1,
					   verdict, *proxy_port, policy_match_type, audited,
					   auth_type);

	if (verdict != CTX_ACT_OK)
		return verdict;

skip_policy_enforcement:
	if (ret == CT_NEW) {
#if defined(ENABLE_NODEPORT) && defined(ENABLE_IPSEC)
		ct_state_new.node_port = ct_has_nodeport_egress_entry6(get_ct_map6(tuple),
								       tuple, NULL, false);
#endif /* ENABLE_NODEPORT && ENABLE_IPSEC */
		ct_state_new.src_sec_id = src_label;
		ct_state_new.from_tunnel = from_tunnel;
		ct_state_new.proxy_redirect = *proxy_port > 0;

		/* ext_err may contain a value from __policy_can_access, and
		 * ct_create6 overwrites it only if it returns an error itself.
		 * As the error from __policy_can_access is dropped in that
		 * case, it's OK to return ext_err from ct_create6 along with
		 * its error code.
		 */
		ret = ct_create6(get_ct_map6(tuple), &CT_MAP_ANY6, tuple, ctx, CT_INGRESS,
				 &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	if (*proxy_port > 0) {
		send_trace_notify6(ctx, TRACE_TO_PROXY, src_label, SECLABEL_IPV6, &orig_sip,
				   bpf_ntohs(*proxy_port), ifindex, trace.reason,
				   trace.monitor);
		if (tuple_out)
			memcpy(tuple_out, tuple, sizeof(*tuple));
		return POLICY_ACT_PROXY_REDIRECT;
	}
	/* Not redirected to host / proxy. */
	send_trace_notify6(ctx, TRACE_TO_LXC, src_label, SECLABEL_IPV6, &orig_sip,
			   LXC_ID, ifindex, trace.reason, trace.monitor);

	return CTX_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY)
static __always_inline
int tail_ipv6_policy(struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple = {};
	int ret, ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	__u32 src_label = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	bool from_host = ctx_load_and_clear_meta(ctx, CB_FROM_HOST);
	bool proxy_redirect __maybe_unused = false;
	bool from_tunnel = false;
	void *data, *data_end;
	__u16 proxy_port = 0;
	struct ipv6hdr *ip6;
	__s8 ext_err = 0;

#ifdef HAVE_ENCAP
	from_tunnel = ctx_load_and_clear_meta(ctx, CB_FROM_TUNNEL);
#endif

	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	ret = ipv6_policy(ctx, ip6, THIS_INTERFACE_IFINDEX, src_label, &tuple,
			  &ext_err, &proxy_port, from_tunnel);
	switch (ret) {
	case POLICY_ACT_PROXY_REDIRECT:
		if (from_tunnel)
			ctx_change_type(ctx, PACKET_HOST);

		ret = ctx_redirect_to_proxy6(ctx, &tuple, proxy_port, from_host);
		proxy_redirect = true;
		break;
	case CTX_ACT_OK:
#if !defined(ENABLE_ROUTING) && !defined(ENABLE_NODEPORT)
		/* See comment in IPv4 path. */
		if (from_tunnel) {
			ctx_change_type(ctx, PACKET_HOST);
			break;
		}
#endif /* !ENABLE_ROUTING && !ENABLE_NODEPORT */

		if (ifindex)
			ret = redirect_ep(ctx, THIS_INTERFACE_IFINDEX, from_host,
					  from_tunnel);
		break;
	default:
		break;
	}

	if (IS_ERR(ret))
		goto drop_err;

	/* Store meta: essential for proxy ingress, see bpf_host.c */
	ctx_store_meta(ctx, CB_PROXY_MAGIC, ctx->mark);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect && !encode_custom_prog_meta(ctx, ret, src_label)) {
		tail_call_static(ctx, CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV6_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;

drop_err:
	return send_drop_notify_ext(ctx, src_label, SECLABEL_IPV6, LXC_ID,
				    ret, ext_err, CTX_ACT_DROP, METRIC_INGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_TO_ENDPOINT)
int tail_ipv6_to_endpoint(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	bool proxy_redirect __maybe_unused = false;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u16 proxy_port = 0;
	__s8 ext_err = 0;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto out;
	}

	if (unlikely(is_icmp6_ndp(ctx, ip6, ETH_HLEN))) {
		ret = CTX_ACT_OK;
		goto out;
	}

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_sec_identity)) {
		union v6addr *src = (union v6addr *)&ip6->saddr;
		struct remote_endpoint_info *info;

		info = lookup_ip6_remote_endpoint(src, 0);
		if (info != NULL) {
			__u32 sec_identity = info->sec_identity;

			if (sec_identity) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "src_sec_identity"
				 * (passed into this function) reports the src
				 * as the host. So we can ignore the ipcache
				 * if it reports the source as HOST_ID.
				 */
				if (sec_identity != HOST_ID)
					src_sec_identity = sec_identity;
			}
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   ((__u32 *)src)[3], src_sec_identity);
	}

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL_IPV6);

#ifdef LOCAL_DELIVERY_METRICS
	update_metrics(ctx_full_len(ctx), METRIC_INGRESS, REASON_FORWARDED);
#endif

	ret = ipv6_policy(ctx, ip6, THIS_INTERFACE_IFINDEX, src_sec_identity,
			  NULL, &ext_err, &proxy_port, false);
	switch (ret) {
	case POLICY_ACT_PROXY_REDIRECT:
		ret = ctx_redirect_to_proxy_hairpin_ipv6(ctx, proxy_port);
		proxy_redirect = true;
		break;
	case CTX_ACT_OK:
		break;
	default:
		break;
	}
out:
	if (IS_ERR(ret))
		return send_drop_notify_ext(ctx, src_sec_identity, SECLABEL_IPV6, LXC_ID,
					ret, ext_err, CTX_ACT_DROP, METRIC_INGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect &&
	    !encode_custom_prog_meta(ctx, ret, src_sec_identity)) {
		tail_call_static(ctx, CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV6_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

TAIL_CT_LOOKUP6(CILIUM_CALL_IPV6_CT_INGRESS_POLICY_ONLY,
		tail_ipv6_ct_ingress_policy_only, CT_INGRESS,
		__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY, tail_ipv6_policy)

TAIL_CT_LOOKUP6(CILIUM_CALL_IPV6_CT_INGRESS, tail_ipv6_ct_ingress, CT_INGRESS,
		1, CILIUM_CALL_IPV6_TO_ENDPOINT, tail_ipv6_to_endpoint)
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int
ipv4_policy(struct __ctx_buff *ctx, struct iphdr *ip4, int ifindex, __u32 src_label,
	    struct ipv4_ct_tuple *tuple_out, __s8 *ext_err, __u16 *proxy_port,
	    bool from_tunnel)
{
	struct ct_state *ct_state, ct_state_new = {};
	struct ipv4_ct_tuple *tuple;
	bool skip_ingress_proxy = false;
	bool is_untracked_fragment = false;
	struct ct_buffer4 *ct_buffer;
	struct trace_ctx trace;
	int ret, verdict, l4_off;
	__be32 orig_sip;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	__u8 auth_type = 0;
	__u32 zero = 0;

	policy_clear_mark(ctx);

	/* If packet is coming from the ingress proxy we have to skip
	 * redirection to the ingress proxy as we would loop forever.
	 */
	skip_ingress_proxy = tc_index_from_ingress_proxy(ctx);

	orig_sip = ip4->saddr;

#ifndef ENABLE_IPV4_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipv4_is_fragment(ip4);
#endif

	ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER4, &zero);
	if (!ct_buffer)
		return DROP_INVALID_TC_BUFFER;
	if (ct_buffer->tuple.saddr == 0)
		/* The map value is zeroed so the map update didn't happen somehow. */
		return DROP_INVALID_TC_BUFFER;

	tuple = (struct ipv4_ct_tuple *)&ct_buffer->tuple;
	ct_state = (struct ct_state *)&ct_buffer->ct_state;
	trace.monitor = ct_buffer->monitor;
	trace.reason = (enum trace_reason)ct_buffer->ret;
	ret = ct_buffer->ret;
	l4_off = ct_buffer->l4_off;

	/* Check it this is return traffic to an egress proxy.
	 * Do not redirect again if the packet is coming from the egress proxy.
	 * Always redirect connections that originated from L7 LB.
	 */
	/* Skip policy enforcement for return traffic. */
	if (ret == CT_REPLY || ret == CT_RELATED) {
		if (ct_state_is_from_l7lb(ct_state) ||
		    (ct_state->proxy_redirect && !tc_index_from_egress_proxy(ctx))) {
			/* This is a reply, the proxy port does not need to be embedded
			 * into ctx->mark and *proxy_port can be left unset.
			 */
			send_trace_notify4(ctx, TRACE_TO_PROXY, src_label, SECLABEL_IPV4, orig_sip,
					   TRACE_EP_ID_UNKNOWN, ifindex, trace.reason,
					   trace.monitor);
			if (tuple_out)
				*tuple_out = *tuple;
			return POLICY_ACT_PROXY_REDIRECT;
		}

		/* Reverse NAT applies to return traffic only. */
		if (unlikely(ct_state->rev_nat_index)) {
			bool has_l4_header = false;
			int ret2;

			has_l4_header = ipv4_has_l4_header(ip4);

			ret2 = lb4_rev_nat(ctx, ETH_HLEN, l4_off,
					   ct_state->rev_nat_index,
					   ct_state->loopback,
					   tuple, has_l4_header);
			if (IS_ERR(ret2))
				return ret2;
		}

		/* proxy_port remains 0 in this case */
		goto skip_policy_enforcement;
	}

	if (skip_ingress_proxy)
		goto skip_policy_enforcement;

#if defined(ENABLE_PER_PACKET_LB) && !defined(DISABLE_LOOPBACK_LB)
	/* When an endpoint connects to itself via service clusterIP, we need
	 * to skip the policy enforcement. If we didn't, the user would have to
	 * define policy rules to allow pods to talk to themselves. We still
	 * want to execute the conntrack logic so that replies can be correctly
	 * matched.
	 *
	 * If ip4.saddr is IPV4_LOOPBACK, this is almost certainly a loopback
	 * connection. Populate
	 * - .loopback, so that policy enforcement is bypassed, and
	 * - .rev_nat_index, so that replies can be RevNATed.
	 */
	if (ret == CT_NEW && ip4->saddr == IPV4_LOOPBACK &&
	    ct_has_loopback_egress_entry4(get_ct_map4(tuple), tuple)) {
		ct_state_new.loopback = true;
		goto skip_policy_enforcement;
	}

	if (unlikely(ct_state->loopback))
		goto skip_policy_enforcement;
#endif /* ENABLE_PER_PACKET_LB && !DISABLE_LOOPBACK_LB */

	verdict = policy_can_ingress4(ctx, &POLICY_MAP, tuple, l4_off, is_untracked_fragment,
				      src_label, SECLABEL_IPV4, &policy_match_type, &audited,
				      ext_err, proxy_port);
	if (verdict == DROP_POLICY_AUTH_REQUIRED) {
		struct remote_endpoint_info *sep = lookup_ip4_remote_endpoint(orig_sip, 0);

		if (sep) {
			auth_type = (__u8)*ext_err;
			verdict = auth_lookup(ctx, SECLABEL_IPV4, src_label,
					      sep->tunnel_endpoint, auth_type);
		}
	}
	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ret != CT_ESTABLISHED)
		send_policy_verdict_notify(ctx, src_label, tuple->dport,
					   tuple->nexthdr, POLICY_INGRESS, 0,
					   verdict, *proxy_port, policy_match_type, audited,
					   auth_type);

	if (verdict != CTX_ACT_OK)
		return verdict;

skip_policy_enforcement:
	if (ret == CT_NEW) {
#if defined(ENABLE_NODEPORT) && defined(ENABLE_IPSEC)
		/* Needed for hostport support, until
		 * https://github.com/cilium/cilium/issues/32897 is fixed.
		 */
		ct_state_new.node_port = ct_has_nodeport_egress_entry4(get_ct_map4(tuple),
								       tuple, NULL, false);
#endif /* ENABLE_NODEPORT && ENABLE_IPSEC */
		ct_state_new.src_sec_id = src_label;
		ct_state_new.from_tunnel = from_tunnel;
		ct_state_new.proxy_redirect = *proxy_port > 0;

		/* ext_err may contain a value from __policy_can_access, and
		 * ct_create4 overwrites it only if it returns an error itself.
		 * As the error from __policy_can_access is dropped in that
		 * case, it's OK to return ext_err from ct_create4 along with
		 * its error code.
		 */
		ret = ct_create4(get_ct_map4(tuple), &CT_MAP_ANY4, tuple, ctx, CT_INGRESS,
				 &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	if (*proxy_port > 0) {
		send_trace_notify4(ctx, TRACE_TO_PROXY, src_label, SECLABEL_IPV4, orig_sip,
				   bpf_ntohs(*proxy_port), ifindex, trace.reason,
				   trace.monitor);
		if (tuple_out)
			*tuple_out = *tuple;
		return POLICY_ACT_PROXY_REDIRECT;
	}
	/* Not redirected to host / proxy. */
	send_trace_notify4(ctx, TRACE_TO_LXC, src_label, SECLABEL_IPV4, orig_sip,
			   LXC_ID, ifindex, trace.reason, trace.monitor);

	return CTX_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY)
static __always_inline
int tail_ipv4_policy(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	int ret, ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	__u32 src_label = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	bool from_host = ctx_load_and_clear_meta(ctx, CB_FROM_HOST);
	bool proxy_redirect __maybe_unused = false;
	bool from_tunnel = false;
	void *data, *data_end;
	__u16 proxy_port = 0;
	struct iphdr *ip4;
	__s8 ext_err = 0;

	ctx_store_meta(ctx, CB_CLUSTER_ID_INGRESS, 0);

#ifdef HAVE_ENCAP
	from_tunnel = ctx_load_and_clear_meta(ctx, CB_FROM_TUNNEL);
#endif

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	ret = ipv4_policy(ctx, ip4, THIS_INTERFACE_IFINDEX, src_label, &tuple,
			  &ext_err, &proxy_port, from_tunnel);
	switch (ret) {
	case POLICY_ACT_PROXY_REDIRECT:
		if (from_tunnel)
			ctx_change_type(ctx, PACKET_HOST);

		ret = ctx_redirect_to_proxy4(ctx, &tuple, proxy_port, from_host);
		proxy_redirect = true;
		break;
	case CTX_ACT_OK:
#if !defined(ENABLE_ROUTING) && !defined(ENABLE_NODEPORT)
		/* In tunneling mode, we execute this code to send the packet from
		 * cilium_vxlan to lxc*. If we're using kube-proxy, we don't want to use
		 * redirect() because that would bypass conntrack and the reverse DNAT.
		 * Thus, we send packets to the stack, but since they have the wrong
		 * Ethernet addresses, we need to mark them as PACKET_HOST or the kernel
		 * will drop them.
		 * See #14646 for details.
		 */
		if (from_tunnel) {
			ctx_change_type(ctx, PACKET_HOST);
			break;
		}
#endif /* !ENABLE_ROUTING && !ENABLE_NODEPORT */

		if (ifindex)
			ret = redirect_ep(ctx, THIS_INTERFACE_IFINDEX, from_host,
					  from_tunnel);
		break;
	default:
		break;
	}

	if (IS_ERR(ret))
		goto drop_err;

	/* Store meta: essential for proxy ingress, see bpf_host.c */
	ctx_store_meta(ctx, CB_PROXY_MAGIC, ctx->mark);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect && !encode_custom_prog_meta(ctx, ret, src_label)) {
		tail_call_static(ctx, CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV4_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;

drop_err:
	return send_drop_notify_ext(ctx, src_label, SECLABEL_IPV4, LXC_ID,
				    ret, ext_err, CTX_ACT_DROP, METRIC_INGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_TO_ENDPOINT)
int tail_ipv4_to_endpoint(struct __ctx_buff *ctx)
{
	__u32 src_sec_identity = ctx_load_and_clear_meta(ctx, CB_SRC_LABEL);
	bool proxy_redirect __maybe_unused = false;
	void *data, *data_end;
	struct iphdr *ip4;
	__u16 proxy_port = 0;
	__s8 ext_err = 0;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto out;
	}

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_sec_identity)) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		if (info != NULL) {
			__u32 sec_identity = info->sec_identity;

			if (sec_identity) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "src_sec_identity"
				 * (passed into this function) reports the src
				 * as the host. So we can ignore the ipcache
				 * if it reports the source as HOST_ID.
				 */
				if (sec_identity != HOST_ID)
					src_sec_identity = sec_identity;
			}
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->saddr, src_sec_identity);
	}

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL_IPV4);

#ifdef LOCAL_DELIVERY_METRICS
	update_metrics(ctx_full_len(ctx), METRIC_INGRESS, REASON_FORWARDED);
#endif

	ret = ipv4_policy(ctx, ip4, THIS_INTERFACE_IFINDEX, src_sec_identity,
			  NULL, &ext_err, &proxy_port, false);
	switch (ret) {
	case POLICY_ACT_PROXY_REDIRECT:
		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto out;
		}

		ret = ctx_redirect_to_proxy_hairpin_ipv4(ctx, ip4, proxy_port);
		proxy_redirect = true;
		break;
	case CTX_ACT_OK:
		break;
	default:
		break;
	}
out:
	if (IS_ERR(ret))
		return send_drop_notify_ext(ctx, src_sec_identity, SECLABEL_IPV4, LXC_ID,
					ret, ext_err, CTX_ACT_DROP, METRIC_INGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect &&
	    !encode_custom_prog_meta(ctx, ret, src_sec_identity)) {
		tail_call_static(ctx, CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV4_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

TAIL_CT_LOOKUP4(CILIUM_CALL_IPV4_CT_INGRESS_POLICY_ONLY,
		tail_ipv4_ct_ingress_policy_only, CT_INGRESS,
		__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY, tail_ipv4_policy)

TAIL_CT_LOOKUP4(CILIUM_CALL_IPV4_CT_INGRESS, tail_ipv4_ct_ingress, CT_INGRESS,
		1, CILIUM_CALL_IPV4_TO_ENDPOINT, tail_ipv4_to_endpoint)
#endif /* ENABLE_IPV4 */

/* Handle policy decisions as the packet makes its way towards the endpoint.
 * Previously, the packet may have come from another local endpoint, another
 * endpoint in the cluster, or from the big blue room (as identified by the
 * contents of ctx / CB_SRC_LABEL. Determine whether the traffic may be
 * passed into the endpoint or if it needs further inspection by a userspace
 * proxy.
 *
 * This program will be tail called to in ipv{4,6}_local_delivery from either
 * bpf_host, bpf_overlay (if coming from the tunnel), or bpf_lxc (if coming
 * from another local pod).
 */
__section_tail(CILIUM_MAP_POLICY, TEMPLATE_LXC_ID)
int handle_policy(struct __ctx_buff *ctx)
{
	__u32 src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
	__u32 sec_label = SECLABEL;
	__s8 ext_err = 0;
	__u16 proto;
	int ret;

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
					 CILIUM_CALL_IPV6_CT_INGRESS_POLICY_ONLY,
					 tail_ipv6_ct_ingress_policy_only, &ext_err);
		sec_label = SECLABEL_IPV6;
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
					 CILIUM_CALL_IPV4_CT_INGRESS_POLICY_ONLY,
					 tail_ipv4_ct_ingress_policy_only, &ext_err);
		sec_label = SECLABEL_IPV4;
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify_ext(ctx, src_label, sec_label, LXC_ID, ret, ext_err,
					    CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}

/* Handle policy decisions as the packet makes its way from the
 * endpoint.  Previously, the packet has come from the same endpoint,
 * but was redirected to a L7 LB.
 *
 * This program will be tail called from bpf_host for packets sent by
 * a L7 LB.
 */
#if defined(ENABLE_L7_LB)
__section_tail(CILIUM_MAP_EGRESSPOLICY, TEMPLATE_LXC_ID)
int handle_policy_egress(struct __ctx_buff *ctx)
{
	__u16 proto;
	int ret;
	__u32 sec_label = SECLABEL;
	__s8 ext_err = 0;

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	ctx_store_meta(ctx, CB_FROM_HOST, FROM_HOST_L7_LB);

	edt_set_aggregate(ctx, 0); /* do not count this traffic again */
	send_trace_notify(ctx, TRACE_FROM_PROXY, SECLABEL, UNKNOWN_ID,
			  TRACE_EP_ID_UNKNOWN, TRACE_IFINDEX_UNKNOWN,
			  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_FROM_LXC, &ext_err);
		sec_label = SECLABEL_IPV6;
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_LXC, &ext_err);
		sec_label = SECLABEL_IPV4;
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify_ext(ctx, sec_label, UNKNOWN_ID,
					    TRACE_EP_ID_UNKNOWN, ret, ext_err,
					    CTX_ACT_DROP, METRIC_EGRESS);

	return ret;
}
#endif

/* Attached to the lxc device on the way to the container, only if endpoint
 * routes are enabled.
 */
__section_entry
int cil_to_container(struct __ctx_buff *ctx)
{
	enum trace_point trace = TRACE_FROM_STACK;
	__u32 magic, identity = 0;
	__u32 sec_label = SECLABEL;
	__s8 ext_err = 0;
	__u16 proto;
	int ret;

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	bpf_clear_meta(ctx);

	magic = inherit_identity_from_host(ctx, &identity);
	if (magic == MARK_MAGIC_PROXY_INGRESS || magic == MARK_MAGIC_PROXY_EGRESS)
		trace = TRACE_FROM_PROXY;
#if defined(ENABLE_L7_LB)
	else if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
		ret = tail_call_egress_policy(ctx, (__u16)identity);
		return send_drop_notify(ctx, identity, sec_label, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);
	}
#endif

	send_trace_notify(ctx, trace, identity, sec_label, LXC_ID,
			  ctx->ingress_ifindex, TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)
	/* If the packet comes from the hostns and per-endpoint routes are enabled,
	 * jump to bpf_host to enforce egress host policies before anything else.
	 *
	 * We will jump back to bpf_lxc once host policies are enforced. Whenever
	 * we call inherit_identity_from_host, the packet mark is cleared. Thus,
	 * when we jump back, the packet mark will have been cleared and the
	 * identity won't match HOST_ID anymore.
	 */
	if (identity == HOST_ID) {
		ctx_store_meta(ctx, CB_FROM_HOST, 1);
		ctx_store_meta(ctx, CB_DST_ENDPOINT_ID, LXC_ID);

		ret = tail_call_policy(ctx, HOST_EP_ID);
		return send_drop_notify(ctx, identity, sec_label, LXC_ID,
					DROP_HOST_NOT_READY, CTX_ACT_DROP,
					METRIC_INGRESS);
	}
#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */


	switch (proto) {
#if defined(ENABLE_ARP_PASSTHROUGH) || defined(ENABLE_ARP_RESPONDER)
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		sec_label = SECLABEL_IPV6;
# ifdef ENABLE_HIGH_SCALE_IPCACHE
	if (identity_is_world_ipv6(identity)) {
		struct endpoint_info *ep;
		void *data, *data_end;
		struct ipv6hdr *ip6;

		if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
			ret = DROP_INVALID;
			goto out;
		}

		ep = __lookup_ip6_endpoint((union v6addr *)&ip6->saddr);
		if (ep)
			identity = ep->sec_id;
	}
# endif /* ENABLE_HIGH_SCALE_IPCACHE */
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_CT_INGRESS, &ext_err);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		sec_label = SECLABEL_IPV4;
# ifdef ENABLE_HIGH_SCALE_IPCACHE
	if (identity_is_world_ipv4(identity)) {
		struct endpoint_info *ep;
		void *data, *data_end;
		struct iphdr *ip4;

		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto out;
		}

		ep = __lookup_ip4_endpoint(ip4->saddr);
		if (ep)
			identity = ep->sec_id;
	}
# endif /* ENABLE_HIGH_SCALE_IPCACHE */
		ctx_store_meta(ctx, CB_SRC_LABEL, identity);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_CT_INGRESS, &ext_err);
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify_ext(ctx, identity, sec_label, LXC_ID, ret,
					    ext_err, CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}

BPF_LICENSE("Dual BSD/GPL");
