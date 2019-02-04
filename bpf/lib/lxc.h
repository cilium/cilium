/*
 *  Copyright (C) 2016-2018 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __LIB_LXC_H_
#define __LIB_LXC_H_

#include "common.h"
#include "utils.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"
#include "trace.h"
#include "csum.h"
#include "l4.h"

#ifndef DISABLE_SIP_VERIFICATION
static inline int is_valid_lxc_src_ip(struct ipv6hdr *ip6)
{
#ifdef LXC_IP
	union v6addr valid = {};

	BPF_V6(valid, LXC_IP);

	return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
#else
	return 0;
#endif
}

static inline int is_valid_lxc_src_ipv4(struct iphdr *ip4)
{
#ifdef LXC_IPV4
	return ip4->saddr == LXC_IPV4;
#else
	/* Can't send IPv4 if no IPv4 address is configured */
	return 0;
#endif
}
#else
static inline int is_valid_lxc_src_ip(struct ipv6hdr *ip6)
{
	return 1;
}

static inline int is_valid_lxc_src_ipv4(struct iphdr *ip4)
{
	return 1;
}
#endif

#ifdef ENABLE_IPV4
static inline void __inline__
ipv4_redirect_to_proxy(struct __sk_buff *skb, struct iphdr *ip4, int ingress,
		       __be16 proxy_port, int forwarding_reason, __u32 monitor)
{
	uint32_t dscp = bpf_ntohs(proxy_port) & 0x3F;

	if (ingress == CT_INGRESS) {
		// Trace the packet before its forwarded to proxy
		send_trace_notify(skb, TRACE_TO_PROXY, SECLABEL, 0, 0, HOST_IFINDEX,
				  forwarding_reason, monitor);

		/* skb->mark gets scrubbed for traffic passing the cilium host veth.
		 * Set the DSCP in the IP header to cover that case.
		 * Note that the skb is destined to the host proxy so the POD will not
		 * see the modified DSCP. */
		ipv4_set_dscp(skb, ip4, dscp);
	} else {
		skb->mark = MARK_MAGIC_TO_PROXY | dscp;
	}
	cilium_dbg_capture(skb, DBG_CAPTURE_PROXY_POST, proxy_port);
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
static inline void __inline__
ipv6_redirect_to_proxy(struct __sk_buff *skb, struct ipv6hdr *ip6, int ingress,
		       __be16 proxy_port, int forwarding_reason, __u32 monitor)
{
	uint32_t dscp = bpf_ntohs(proxy_port) & 0x3F;

	if (ingress == CT_INGRESS) {
		// Trace the packet before its destination address and port are rewritten.
		send_trace_notify(skb, TRACE_TO_PROXY, SECLABEL, 0, 0, HOST_IFINDEX,
				  forwarding_reason, monitor);

		/* skb->mark gets scrubbed for traffic passing the cilium host veth.
		 * Set the DSCP in the IP header to cover that case.
		 * Note that the skb is destined to the host proxy so the POD will not
		 * see the modified DSCP. */
		ipv6_set_dscp(skb, ip6, dscp);
	} else {
		skb->mark = MARK_MAGIC_TO_PROXY | dscp;
	}
	cilium_dbg_capture(skb, DBG_CAPTURE_PROXY_POST, proxy_port);
}
#endif /* ENABLE_IPV6 */

/**
 * tc_index_is_from_proxy - returns true if packet originates from ingress proxy
 */
static inline bool __inline__ tc_index_skip_proxy(struct __sk_buff *skb)
{
	volatile __u32 tc_index = skb->tc_index;
#ifdef DEBUG
	if (tc_index & TC_INDEX_F_SKIP_PROXY)
		cilium_dbg(skb, DBG_SKIP_PROXY, tc_index, 0);
#endif

	return tc_index & TC_INDEX_F_SKIP_PROXY;
}
#endif /* __LIB_LXC_H_ */
