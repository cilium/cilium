/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_HOST_FIREWALL_H_
#define __LIB_HOST_FIREWALL_H_

/* Only compile in if host firewall is enabled and file is included from
 * bpf_host.
 */
#if defined(ENABLE_HOST_FIREWALL) && defined(HOST_EP_ID)

# include "policy.h"
# include "policy_log.h"

# ifdef ENABLE_IPV6
static __always_inline int
ipv6_host_policy_egress(struct __ctx_buff *ctx, __u32 src_id)
{
	int ret, verdict, l3_off = ETH_HLEN, l4_off, hdrlen;
	struct ct_state ct_state_new = {}, ct_state = {};
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	struct remote_endpoint_info *info;
	struct ipv6_ct_tuple tuple = {};
	__u32 dst_id = 0, monitor = 0;
	union v6addr orig_dip;
	void *data, *data_end;
	struct ipv6hdr *ip6;

	/* Only enforce host policies for packets from host IPs. */
	if (src_id != HOST_ID)
		return CTX_ACT_OK;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Lookup connection in conntrack map. */
	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);
	ipv6_addr_copy(&orig_dip, (union v6addr *)&ip6->daddr);
	hdrlen = ipv6_hdrlen(ctx, ETH_HLEN, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;
	l4_off = l3_off + hdrlen;
	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;

	/* Retrieve destination identity. */
	info = lookup_ip6_remote_endpoint(&orig_dip);
	if (info && info->sec_label)
		dst_id = info->sec_label;
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
		   orig_dip.p4, dst_id);

	/* Perform policy lookup. */
	verdict = policy_can_egress6(ctx, &tuple, src_id, dst_id,
				     &policy_match_type, &audited);

	/* Reply traffic and related are allowed regardless of policy verdict. */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, dst_id, tuple.dport,
					   tuple.nexthdr, POLICY_EGRESS, 1,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	switch (ret) {
	case CT_NEW:
		send_policy_verdict_notify(ctx, dst_id, tuple.dport,
					   tuple.nexthdr, POLICY_EGRESS, 1,
					   verdict, policy_match_type, audited);
		ct_state_new.src_sec_id = HOST_ID;
		ret = ct_create6(get_ct_map6(&tuple), &CT_MAP_ANY6, &tuple,
				 ctx, CT_EGRESS, &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;
		break;

	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	return CTX_ACT_OK;
}

static __always_inline int
ipv6_host_policy_ingress(struct __ctx_buff *ctx, __u32 *src_id)
{
	struct ct_state ct_state_new = {}, ct_state = {};
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	__u32 monitor = 0, dst_id = WORLD_ID;
	struct remote_endpoint_info *info;
	int ret, verdict, l4_off, hdrlen;
	struct ipv6_ct_tuple tuple = {};
	union v6addr orig_sip;
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Retrieve destination identity. */
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);
	info = lookup_ip6_remote_endpoint(&tuple.daddr);
	if (info && info->sec_label)
		dst_id = info->sec_label;
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
		   tuple.daddr.p4, dst_id);

	/* Only enforce host policies for packets to host IPs. */
	if (dst_id != HOST_ID)
		return CTX_ACT_OK;

	/* Lookup connection in conntrack map. */
	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&orig_sip, (union v6addr *)&ip6->saddr);
	hdrlen = ipv6_hdrlen(ctx, ETH_HLEN, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;
	l4_off = ETH_HLEN + hdrlen;
	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, CT_INGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;

	/* Retrieve source identity. */
	info = lookup_ip6_remote_endpoint(&orig_sip);
	if (info && info->sec_label)
		*src_id = info->sec_label;
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
		   orig_sip.p4, *src_id);

	/* Perform policy lookup */
	verdict = policy_can_access_ingress(ctx, *src_id, dst_id, tuple.dport,
					    tuple.nexthdr, false,
					    &policy_match_type, &audited);

	/* Reply traffic and related are allowed regardless of policy verdict. */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, *src_id, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 1,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	switch (ret) {
	case CT_NEW:
		send_policy_verdict_notify(ctx, *src_id, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 1,
					   verdict, policy_match_type, audited);

		/* Create new entry for connection in conntrack map. */
		ct_state_new.src_sec_id = *src_id;
		ct_state_new.node_port = ct_state.node_port;
		ret = ct_create6(get_ct_map6(&tuple), &CT_MAP_ANY6, &tuple,
				 ctx, CT_INGRESS, &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;

	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	/* This change is necessary for packets redirected from the lxc device to
	 * the host device.
	 */
	ctx_change_type(ctx, PACKET_HOST);
	return CTX_ACT_OK;
}
# endif /* ENABLE_IPV6 */

# ifdef ENABLE_IPV4
#  ifndef ENABLE_MASQUERADE
static __always_inline int
whitelist_snated_egress_connections(struct __ctx_buff *ctx, __u32 ipcache_srcid)
{
	struct ct_state ct_state_new = {}, ct_state = {};
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	__u32 monitor = 0;
	int ret, l4_off;

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
	if (ipcache_srcid == HOST_ID) {
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		tuple.nexthdr = ip4->protocol;
		tuple.daddr = ip4->daddr;
		tuple.saddr = ip4->saddr;
		l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
		ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off,
				 CT_EGRESS, &ct_state, &monitor);
		if (ret < 0)
			return ret;
		if (ret == CT_NEW) {
			ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4,
					 &tuple, ctx, CT_EGRESS, &ct_state_new,
					 false);
			if (IS_ERR(ret))
				return ret;
		}
	}

	return CTX_ACT_OK;
}
#   endif

static __always_inline int
ipv4_host_policy_egress(struct __ctx_buff *ctx, __u32 src_id,
			__u32 ipcache_srcid __maybe_unused)
{
	struct ct_state ct_state_new = {}, ct_state = {};
	int ret, verdict, l4_off, l3_off = ETH_HLEN;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	struct remote_endpoint_info *info;
	struct ipv4_ct_tuple tuple = {};
	__u32 dst_id = 0, monitor = 0;
	void *data, *data_end;
	struct iphdr *ip4;

	if (src_id != HOST_ID) {
#  ifndef ENABLE_MASQUERADE
		return whitelist_snated_egress_connections(ctx, ipcache_srcid);
#  else
		/* Only enforce host policies for packets from host IPs. */
		return CTX_ACT_OK;
#  endif
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* Lookup connection in conntrack map. */
	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	l4_off = l3_off + ipv4_hdrlen(ip4);
	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;

	/* Retrieve destination identity. */
	info = lookup_ip4_remote_endpoint(ip4->daddr);
	if (info && info->sec_label)
		dst_id = info->sec_label;
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
		   ip4->daddr, dst_id);

	/* Perform policy lookup. */
	verdict = policy_can_egress4(ctx, &tuple, src_id, dst_id,
				     &policy_match_type, &audited);

	/* Reply traffic and related are allowed regardless of policy verdict. */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, dst_id, tuple.dport,
					   tuple.nexthdr, POLICY_EGRESS, 0,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	switch (ret) {
	case CT_NEW:
		send_policy_verdict_notify(ctx, dst_id, tuple.dport,
					   tuple.nexthdr, POLICY_EGRESS, 0,
					   verdict, policy_match_type, audited);
		ct_state_new.src_sec_id = HOST_ID;
		ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple,
				 ctx, CT_EGRESS, &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;
		break;

	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	return CTX_ACT_OK;
}

static __always_inline int
ipv4_host_policy_ingress(struct __ctx_buff *ctx, __u32 *src_id)
{
	struct ct_state ct_state_new = {}, ct_state = {};
	int ret, verdict, l4_off, l3_off = ETH_HLEN;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	__u32 monitor = 0, dst_id = WORLD_ID;
	struct remote_endpoint_info *info;
	struct ipv4_ct_tuple tuple = {};
	bool is_untracked_fragment = false;
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* Retrieve destination identity. */
	info = lookup_ip4_remote_endpoint(ip4->daddr);
	if (info && info->sec_label)
		dst_id = info->sec_label;
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
		   ip4->daddr, dst_id);

	/* Only enforce host policies for packets to host IPs. */
	if (dst_id != HOST_ID)
		return CTX_ACT_OK;

	/* Lookup connection in conntrack map. */
	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	l4_off = l3_off + ipv4_hdrlen(ip4);
#  ifndef IPV4_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipv4_is_fragment(ip4);
#  endif
	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_INGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;

	/* Retrieve source identity. */
	info = lookup_ip4_remote_endpoint(ip4->saddr);
	if (info && info->sec_label)
		*src_id = info->sec_label;
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
		   ip4->saddr, *src_id);

	/* Perform policy lookup */
	verdict = policy_can_access_ingress(ctx, *src_id, dst_id, tuple.dport,
					    tuple.nexthdr,
					    is_untracked_fragment,
					    &policy_match_type, &audited);

	/* Reply traffic and related are allowed regardless of policy verdict. */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, *src_id, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 0,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	switch (ret) {
	case CT_NEW:
		send_policy_verdict_notify(ctx, *src_id, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 0,
					   verdict, policy_match_type, audited);

		/* Create new entry for connection in conntrack map. */
		ct_state_new.src_sec_id = *src_id;
		ct_state_new.node_port = ct_state.node_port;
		ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple,
				 ctx, CT_INGRESS, &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;

	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	/* This change is necessary for packets redirected from the lxc device to
	 * the host device.
	 */
	ctx_change_type(ctx, PACKET_HOST);
	return CTX_ACT_OK;
}
# endif /* ENABLE_IPV4 */
#endif /* ENABLE_HOST_FIREWALL && HOST_EP_ID */
#endif /* __LIB_HOST_FIREWALL_H_ */
