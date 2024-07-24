/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Only compile in if host firewall is enabled and file is included from
 * bpf_host.
 */
#if defined(ENABLE_HOST_FIREWALL) && defined(IS_BPF_HOST)

#include "auth.h"
#include "policy.h"
#include "policy_log.h"
#include "proxy_hairpin.h"
#include "trace.h"

#define ENABLE_HOST_PROXY

# ifdef ENABLE_IPV6
#  ifndef ENABLE_MASQUERADE_IPV6
static __always_inline int
ipv6_whitelist_snated_egress_connections(struct __ctx_buff *ctx, struct ipv6_ct_tuple *tuple,
					 enum ct_status ct_ret, __s8 *ext_err)
{
	/* If kube-proxy is in use (no BPF-based masquerading), packets from
	 * pods may be SNATed. The response packet will therefore have a host
	 * IP as the destination IP.
	 * To avoid enforcing host policies for response packets to pods, we
	 * need to create a CT entry for the forward, SNATed packet from the
	 * pod. Response packets will thus match this CT entry and bypass host
	 * policies.
	 * We know the packet is a SNATed packet if the srcid from ipcache is
	 * HOST_ID, but the actual srcid (derived from the packet mark) isn't.
	 */
	if (ct_ret == CT_NEW) {
		int ret = ct_create6(get_ct_map6(tuple), &CT_MAP_ANY6,
				     tuple, ctx, CT_EGRESS, NULL, ext_err);
		if (unlikely(ret < 0))
			return ret;
	}

	return CTX_ACT_OK;
}
#  endif /* ENABLE_MASQUERADE_IPV6 */

static __always_inline bool
ipv6_host_policy_egress_lookup(struct __ctx_buff *ctx, __u32 src_sec_identity,
			       __u32 ipcache_srcid, struct ipv6hdr *ip6,
			       struct ct_buffer6 *ct_buffer)
{
	struct ipv6_ct_tuple *tuple = &ct_buffer->tuple;
	int l3_off = ETH_HLEN, hdrlen;

	/* Further action is needed in two cases:
	 * 1. Packets from host IPs: need to enforce host policies.
	 * 2. SNATed packets from pods: need to create a CT entry to skip
	 *    applying host policies to reply packets
	 *    (see ipv6_whitelist_snated_egress_connections).
	 */
	if (src_sec_identity != HOST_ID &&
	    (is_defined(ENABLE_MASQUERADE_IPV6) || ipcache_srcid != HOST_ID))
		return false;

	/* Lookup connection in conntrack map. */
	tuple->nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple->saddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple->daddr, (union v6addr *)&ip6->daddr);
	hdrlen = ipv6_hdrlen(ctx, &tuple->nexthdr);
	if (hdrlen < 0) {
		ct_buffer->ret = hdrlen;
		return true;
	}
	ct_buffer->l4_off = l3_off + hdrlen;
	ct_buffer->ret = ct_lookup6(get_ct_map6(tuple), tuple, ctx, ct_buffer->l4_off,
				    CT_EGRESS, NULL, &ct_buffer->monitor);
	return true;
}

static __always_inline int
__ipv6_host_policy_egress(struct __ctx_buff *ctx, bool is_host_id __maybe_unused,
			  struct ipv6hdr *ip6, struct ct_buffer6 *ct_buffer,
			  struct trace_ctx *trace, __s8 *ext_err)
{
	struct ipv6_ct_tuple *tuple = &ct_buffer->tuple;
	__u32 tunnel_endpoint = 0;
	int ret = ct_buffer->ret;
	int verdict;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	__u8 auth_type = 0;
	struct remote_endpoint_info *info;
	__u32 dst_sec_identity = 0;
	__u16 proxy_port = 0;

	trace->monitor = ct_buffer->monitor;
	trace->reason = (enum trace_reason)ret;

#  ifndef ENABLE_MASQUERADE_IPV6
	if (!is_host_id)
		/* Checked in ipv6_host_policy_egress_lookup: src_id == HOST_ID. */
		return ipv6_whitelist_snated_egress_connections(ctx, tuple, (enum ct_status)ret,
							   ext_err);
#  endif /* ENABLE_MASQUERADE_IPV6 */

	/* Retrieve destination identity. */
	info = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
	if (info && info->sec_identity) {
		dst_sec_identity = info->sec_identity;
		tunnel_endpoint = info->tunnel_endpoint;
	}
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
		   ip6->daddr.s6_addr32[3], dst_sec_identity);

	/* Reply traffic and related are allowed regardless of policy verdict. */
	if (ret == CT_REPLY || ret == CT_RELATED)
		return CTX_ACT_OK;

	/* Perform policy lookup. */
	verdict = policy_can_egress6(ctx, &POLICY_MAP, tuple, ct_buffer->l4_off, HOST_ID,
				     dst_sec_identity, &policy_match_type, &audited, ext_err,
				     &proxy_port);
	if (verdict == DROP_POLICY_AUTH_REQUIRED) {
		auth_type = (__u8)*ext_err;
		verdict = auth_lookup(ctx, HOST_ID, dst_sec_identity, tunnel_endpoint, auth_type);
	}

	/* Only create CT entry for accepted connections */
	if (ret == CT_NEW && verdict == CTX_ACT_OK) {
		struct ct_state ct_state_new = {};

		ct_state_new.src_sec_id = HOST_ID;
		ct_state_new.proxy_redirect = proxy_port > 0;

		/* ext_err may contain a value from __policy_can_access, and
		 * ct_create6 overwrites it only if it returns an error itself.
		 * As the error from __policy_can_access is dropped in that
		 * case, it's OK to return ext_err from ct_create6 along with
		 * its error code.
		 */
		ret = ct_create6(get_ct_map6(tuple), &CT_MAP_ANY6, tuple,
				 ctx, CT_EGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ret != CT_ESTABLISHED)
		send_policy_verdict_notify(ctx, dst_sec_identity, tuple->dport,
					   tuple->nexthdr, POLICY_EGRESS, 1,
					   verdict, proxy_port, policy_match_type, audited,
					   auth_type);
	return verdict;
}

static __always_inline int
ipv6_host_policy_egress(struct __ctx_buff *ctx, __u32 src_id,
			__u32 ipcache_srcid, struct ipv6hdr *ip6,
			struct trace_ctx *trace, __s8 *ext_err)
{
	struct ct_buffer6 ct_buffer = {};

	if (!ipv6_host_policy_egress_lookup(ctx, src_id, ipcache_srcid, ip6, &ct_buffer))
		return CTX_ACT_OK;
	if (ct_buffer.ret < 0)
		return ct_buffer.ret;

	return __ipv6_host_policy_egress(ctx, src_id == HOST_ID,
					ip6, &ct_buffer, trace, ext_err);
}

static __always_inline bool
ipv6_host_policy_ingress_lookup(struct __ctx_buff *ctx, struct ipv6hdr *ip6,
				struct ct_buffer6 *ct_buffer)
{
	__u32 dst_sec_identity = WORLD_IPV6_ID;
	struct remote_endpoint_info *info;
	struct ipv6_ct_tuple *tuple = &ct_buffer->tuple;
	int hdrlen;

	/* Retrieve destination identity. */
	ipv6_addr_copy(&tuple->daddr, (union v6addr *)&ip6->daddr);
	info = lookup_ip6_remote_endpoint(&tuple->daddr, 0);
	if (info && info->sec_identity)
		dst_sec_identity = info->sec_identity;
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
		   tuple->daddr.p4, dst_sec_identity);

	/* Only enforce host policies for packets to host IPs. */
	if (dst_sec_identity != HOST_ID)
		return false;

	/* Lookup connection in conntrack map. */
	tuple->nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple->saddr, (union v6addr *)&ip6->saddr);
	hdrlen = ipv6_hdrlen(ctx, &tuple->nexthdr);
	if (hdrlen < 0) {
		ct_buffer->ret = hdrlen;
		return true;
	}
	ct_buffer->l4_off = ETH_HLEN + hdrlen;
	ct_buffer->ret = ct_lookup6(get_ct_map6(tuple), tuple, ctx, ct_buffer->l4_off,
				    CT_INGRESS, NULL, &ct_buffer->monitor);

	return true;
}

static __always_inline int
__ipv6_host_policy_ingress(struct __ctx_buff *ctx, struct ipv6hdr *ip6,
			   struct ct_buffer6 *ct_buffer, __u32 *src_sec_identity,
			   struct trace_ctx *trace, __s8 *ext_err)
{
	struct ipv6_ct_tuple *tuple = &ct_buffer->tuple;
	__u32 tunnel_endpoint = 0;
	int ret = ct_buffer->ret;
	int verdict = CTX_ACT_OK;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	__u8 auth_type = 0;
	struct remote_endpoint_info *info;
	__u16 proxy_port = 0;

	trace->monitor = ct_buffer->monitor;
	trace->reason = (enum trace_reason)ret;

	/* Retrieve source identity. */
	info = lookup_ip6_remote_endpoint((union v6addr *)&ip6->saddr, 0);
	if (info && info->sec_identity) {
		*src_sec_identity = info->sec_identity;
		tunnel_endpoint = info->tunnel_endpoint;
	}
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
		   ip6->saddr.s6_addr32[3], *src_sec_identity);

	/* Reply traffic and related are allowed regardless of policy verdict. */
	if (ret == CT_REPLY || ret == CT_RELATED)
		goto out;

	/* Perform policy lookup */
	verdict = policy_can_ingress6(ctx, &POLICY_MAP, tuple, ct_buffer->l4_off,
				      *src_sec_identity, HOST_ID, &policy_match_type, &audited,
				      ext_err, &proxy_port);
	if (verdict == DROP_POLICY_AUTH_REQUIRED) {
		auth_type = (__u8)*ext_err;
		verdict = auth_lookup(ctx, HOST_ID, *src_sec_identity, tunnel_endpoint, auth_type);
	}

	/* Only create CT entry for accepted connections */
	if (ret == CT_NEW && verdict == CTX_ACT_OK) {
		struct ct_state ct_state_new = {};

		/* Create new entry for connection in conntrack map. */
		ct_state_new.src_sec_id = *src_sec_identity;
		ct_state_new.proxy_redirect = proxy_port > 0;

		/* ext_err may contain a value from __policy_can_access, and
		 * ct_create6 overwrites it only if it returns an error itself.
		 * As the error from __policy_can_access is dropped in that
		 * case, it's OK to return ext_err from ct_create6 along with
		 * its error code.
		 */
		ret = ct_create6(get_ct_map6(tuple), &CT_MAP_ANY6, tuple,
				 ctx, CT_INGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ret != CT_ESTABLISHED)
		send_policy_verdict_notify(ctx, *src_sec_identity, tuple->dport,
					   tuple->nexthdr, POLICY_INGRESS, 1,
					   verdict, proxy_port, policy_match_type, audited,
					   auth_type);
out:
	/* This change is necessary for packets redirected from the lxc device to
	 * the host device.
	 */
	ctx_change_type(ctx, PACKET_HOST);
	return verdict;
}

static __always_inline int
ipv6_host_policy_ingress(struct __ctx_buff *ctx, __u32 *src_sec_identity,
			 struct trace_ctx *trace, __s8 *ext_err)
{
	struct ct_buffer6 ct_buffer = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	if (!ipv6_host_policy_ingress_lookup(ctx, ip6, &ct_buffer))
		return CTX_ACT_OK;
	if (ct_buffer.ret < 0)
		return ct_buffer.ret;

	return __ipv6_host_policy_ingress(ctx, ip6, &ct_buffer, src_sec_identity, trace, ext_err);
}
# endif /* ENABLE_IPV6 */

# ifdef ENABLE_IPV4
#  ifndef ENABLE_MASQUERADE_IPV4
static __always_inline int
ipv4_whitelist_snated_egress_connections(struct __ctx_buff *ctx, struct ipv4_ct_tuple *tuple,
					 enum ct_status ct_ret, __s8 *ext_err)
{
	/* If kube-proxy is in use (no BPF-based masquerading), packets from
	 * pods may be SNATed. The response packet will therefore have a host
	 * IP as the destination IP.
	 * To avoid enforcing host policies for response packets to pods, we
	 * need to create a CT entry for the forward, SNATed packet from the
	 * pod. Response packets will thus match this CT entry and bypass host
	 * policies.
	 * We know the packet is a SNATed packet if the srcid from ipcache is
	 * HOST_ID, but the actual srcid (derived from the packet mark) isn't.
	 */
	if (ct_ret == CT_NEW) {
		int ret = ct_create4(get_ct_map4(tuple), &CT_MAP_ANY4,
				     tuple, ctx, CT_EGRESS, NULL, ext_err);
		if (unlikely(ret < 0))
			return ret;
	}

	return CTX_ACT_OK;
}
#  endif /* ENABLE_MASQUERADE_IPV4 */

static __always_inline bool
ipv4_host_policy_egress_lookup(struct __ctx_buff *ctx, __u32 src_sec_identity,
			       __u32 ipcache_srcid, struct iphdr *ip4,
			       struct ct_buffer4 *ct_buffer)
{
	struct ipv4_ct_tuple *tuple = &ct_buffer->tuple;
	int l3_off = ETH_HLEN;

	/* Further action is needed in two cases:
	 * 1. Packets from host IPs: need to enforce host policies.
	 * 2. SNATed packets from pods: need to create a CT entry to skip
	 *    applying host policies to reply packets.
	 */
	if (src_sec_identity != HOST_ID &&
	    (is_defined(ENABLE_MASQUERADE_IPV4) || ipcache_srcid != HOST_ID))
		return false;

	/* Lookup connection in conntrack map. */
	tuple->nexthdr = ip4->protocol;
	tuple->daddr = ip4->daddr;
	tuple->saddr = ip4->saddr;
	ct_buffer->l4_off = l3_off + ipv4_hdrlen(ip4);
	ct_buffer->ret = ct_lookup4(get_ct_map4(tuple), tuple, ctx, ip4, ct_buffer->l4_off,
				    CT_EGRESS, NULL, &ct_buffer->monitor);
	return true;
}

static __always_inline int
__ipv4_host_policy_egress(struct __ctx_buff *ctx, bool is_host_id __maybe_unused,
			  struct iphdr *ip4, struct ct_buffer4 *ct_buffer,
			  struct trace_ctx *trace, __s8 *ext_err)
{
	struct ipv4_ct_tuple *tuple = &ct_buffer->tuple;
	__u32 tunnel_endpoint = 0;
	int ret = ct_buffer->ret;
	int verdict;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	__u8 auth_type = 0;
	struct remote_endpoint_info *info;
	__u32 dst_sec_identity = 0;
	__u16 proxy_port = 0;
	union macaddr mac = THIS_INTERFACE_MAC;

	trace->monitor = ct_buffer->monitor;
	trace->reason = (enum trace_reason)ret;

#  ifndef ENABLE_MASQUERADE_IPV4
	if (!is_host_id)
		/* Checked in ipv4_host_policy_egress_lookup: ipcache_srcid == HOST_ID. */
		return ipv4_whitelist_snated_egress_connections(ctx, tuple, (enum ct_status)ret,
							   ext_err);
#  endif /* ENABLE_MASQUERADE_IPV4 */

	/* Retrieve destination identity. */
	info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
	if (info && info->sec_identity) {
		dst_sec_identity = info->sec_identity;
		tunnel_endpoint = info->tunnel_endpoint;
	}
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
		   ip4->daddr, dst_sec_identity);

	/* Reply traffic and related are allowed regardless of policy verdict. */
	if (ret == CT_REPLY || ret == CT_RELATED)
		return CTX_ACT_OK;

	/* Perform policy lookup. */
	verdict = policy_can_egress4(ctx, &POLICY_MAP, tuple, ct_buffer->l4_off, HOST_ID,
				     dst_sec_identity, &policy_match_type,
				     &audited, ext_err, &proxy_port);
	if (verdict == DROP_POLICY_AUTH_REQUIRED) {
		auth_type = (__u8)*ext_err;
		verdict = auth_lookup(ctx, HOST_ID, dst_sec_identity, tunnel_endpoint, auth_type);
	}

	/* Only create CT entry for accepted connections */
	if (ret == CT_NEW && verdict == CTX_ACT_OK) {
		struct ct_state ct_state_new = {};

		ct_state_new.src_sec_id = HOST_ID;
		ct_state_new.proxy_redirect = proxy_port > 0;

		/* ext_err may contain a value from __eolicy_can_access, and
		 * ct_create4 overwrites it only if it returns an error itself.
		 * As the error from __policy_can_access is dropped in that
		 * case, it's OK to return ext_err from ct_create4 along with
		 * its error code.
		 */
		ret = ct_create4(get_ct_map4(tuple), &CT_MAP_ANY4, tuple,
				 ctx, CT_EGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ret != CT_ESTABLISHED)
		send_policy_verdict_notify(ctx, dst_sec_identity, tuple->dport,
					   tuple->nexthdr, POLICY_EGRESS, 0,
					   verdict, proxy_port, policy_match_type, audited,
					   auth_type);

#  ifdef ENABLE_HOST_PROXY
	if (proxy_port > 0 && (ret == CT_NEW || ret == CT_ESTABLISHED)) {
		/* Trace the packet before it is forwarded to proxy */
		send_trace_notify(ctx, TRACE_TO_PROXY, SECLABEL_IPV4, UNKNOWN_ID,
				bpf_ntohs(proxy_port), TRACE_IFINDEX_UNKNOWN,
				trace->reason, trace->monitor);
		ret = ctx_redirect_to_proxy4(ctx, tuple, proxy_port, false);
		if (IS_ERR(ret))
			return ret;
		eth_store_daddr(ctx, (__u8 *)&mac, 0);
		return ctx_redirect(ctx, NATIVE_DEV_IFINDEX, BPF_F_INGRESS);
	}
#  endif /* ENABLE_HOST_PROXY */

	return verdict;
}

static __always_inline int
ipv4_host_policy_egress(struct __ctx_buff *ctx, __u32 src_id,
			__u32 ipcache_srcid, struct iphdr *ip4,
			struct trace_ctx *trace, __s8 *ext_err)
{
	struct ct_buffer4 ct_buffer = {};

	if (!ipv4_host_policy_egress_lookup(ctx, src_id, ipcache_srcid, ip4, &ct_buffer))
		return CTX_ACT_OK;
	if (ct_buffer.ret < 0)
		return ct_buffer.ret;

	return __ipv4_host_policy_egress(ctx, src_id == HOST_ID, ip4, &ct_buffer, trace, ext_err);
}

static __always_inline bool
ipv4_host_policy_ingress_lookup(struct __ctx_buff *ctx, struct iphdr *ip4,
				struct ct_buffer4 *ct_buffer)
{
	__u32 dst_sec_identity = WORLD_IPV4_ID;
	struct remote_endpoint_info *info;
	struct ipv4_ct_tuple *tuple = &ct_buffer->tuple;
	int l3_off = ETH_HLEN;

	/* Retrieve destination identity. */
	info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
	if (info && info->sec_identity)
		dst_sec_identity = info->sec_identity;
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
		   ip4->daddr, dst_sec_identity);

	/* Only enforce host policies for packets to host IPs. */
	if (dst_sec_identity != HOST_ID)
		return false;

	/* Lookup connection in conntrack map. */
	tuple->nexthdr = ip4->protocol;
	tuple->daddr = ip4->daddr;
	tuple->saddr = ip4->saddr;
	ct_buffer->l4_off = l3_off + ipv4_hdrlen(ip4);
	ct_buffer->ret = ct_lookup4(get_ct_map4(tuple), tuple, ctx, ip4, ct_buffer->l4_off,
				    CT_INGRESS, NULL, &ct_buffer->monitor);

	return true;
}

static __always_inline int
__ipv4_host_policy_ingress(struct __ctx_buff *ctx, struct iphdr *ip4,
			   struct ct_buffer4 *ct_buffer, __u32 *src_sec_identity,
			   struct trace_ctx *trace, __s8 *ext_err)
{
	struct ipv4_ct_tuple *tuple = &ct_buffer->tuple;
	__u32 tunnel_endpoint = 0;
	int ret = ct_buffer->ret;
	int verdict = CTX_ACT_OK;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	__u8 auth_type = 0;
	struct remote_endpoint_info *info;
	bool is_untracked_fragment = false;
	__u16 proxy_port = 0;

	trace->monitor = ct_buffer->monitor;
	trace->reason = (enum trace_reason)ret;

	/* Retrieve source identity. */
	info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
	if (info && info->sec_identity) {
		*src_sec_identity = info->sec_identity;
		tunnel_endpoint = info->tunnel_endpoint;
	}
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
		   ip4->saddr, *src_sec_identity);

	/* Reply traffic and related are allowed regardless of policy verdict. */
	if (ret == CT_REPLY || ret == CT_RELATED)
		goto out;

#  ifndef ENABLE_IPV4_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipv4_is_fragment(ip4);
#  endif

	/* Perform policy lookup */
	verdict = policy_can_ingress4(ctx, &POLICY_MAP, tuple, ct_buffer->l4_off,
				      is_untracked_fragment, *src_sec_identity, HOST_ID,
				      &policy_match_type, &audited, ext_err, &proxy_port);
	if (verdict == DROP_POLICY_AUTH_REQUIRED) {
		auth_type = (__u8)*ext_err;
		verdict = auth_lookup(ctx, HOST_ID, *src_sec_identity, tunnel_endpoint, auth_type);
	}

	/* Only create CT entry for accepted connections */
	if (ret == CT_NEW && verdict == CTX_ACT_OK) {
		struct ct_state ct_state_new = {};

		/* Create new entry for connection in conntrack map. */
		ct_state_new.src_sec_id = *src_sec_identity;
		ct_state_new.proxy_redirect = proxy_port > 0;

		/* ext_err may contain a value from __policy_can_access, and
		 * ct_create4 overwrites it only if it returns an error itself.
		 * As the error from __policy_can_access is dropped in that
		 * case, it's OK to return ext_err from ct_create4 along with
		 * its error code.
		 */
		ret = ct_create4(get_ct_map4(tuple), &CT_MAP_ANY4, tuple,
				 ctx, CT_INGRESS, &ct_state_new, ext_err);
		if (IS_ERR(ret))
			return ret;
	}

	/* Emit verdict if drop or if allow for CT_NEW. */
	if (verdict != CTX_ACT_OK || ret != CT_ESTABLISHED)
		send_policy_verdict_notify(ctx, *src_sec_identity, tuple->dport,
					   tuple->nexthdr, POLICY_INGRESS, 0,
					   verdict, proxy_port, policy_match_type, audited,
					   auth_type);
out:
	/* This change is necessary for packets redirected from the lxc device to
	 * the host device.
	 */
	ctx_change_type(ctx, PACKET_HOST);
	return verdict;
}

static __always_inline int
ipv4_host_policy_ingress(struct __ctx_buff *ctx, __u32 *src_sec_identity,
			 struct trace_ctx *trace, __s8 *ext_err)
{
	struct ct_buffer4 ct_buffer = {};
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	if (!ipv4_host_policy_ingress_lookup(ctx, ip4, &ct_buffer))
		return CTX_ACT_OK;
	if (ct_buffer.ret < 0)
		return ct_buffer.ret;

	return __ipv4_host_policy_ingress(ctx, ip4, &ct_buffer, src_sec_identity, trace, ext_err);
}
# endif /* ENABLE_IPV4 */
#endif /* ENABLE_HOST_FIREWALL && IS_BPF_HOST */
