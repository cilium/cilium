/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "utils.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"
#include "trace.h"
#include "l4.h"
#include "l2_responder_maps.h"
#include "proxy.h"
#include "proxy_hairpin.h"

#ifdef ENABLE_SIP_VERIFICATION
static __always_inline
int is_valid_lxc_src_ip(struct ipv6hdr *ip6 __maybe_unused)
{
#ifdef ENABLE_IPV6
	union v6addr valid = CONFIG(endpoint_ipv6);

	if (ipv6_addr_equals((union v6addr *)&ip6->saddr, &valid))
		return 1;

	/* Allow a saddr that is a Service VIP this node currently
	 * L2-announces. An in-pod module (e.g. the kernel AMT relay) may be
	 * configured with a Service ExternalIP/LoadBalancer VIP and legitimately
	 * source packets from it. Only consult the responder map when L2
	 * announcements are enabled — otherwise this is a pure DROP path.
	 */
	if (CONFIG(enable_l2_announcements)) {
		struct l2_responder_v6_key l2key = {};

		l2key.ifindex = CONFIG(direct_routing_dev_ifindex);
		ipv6_addr_copy(&l2key.ip6, (union v6addr *)&ip6->saddr);
		if (map_lookup_elem(&cilium_l2_responder_v6, &l2key))
			return 1;
	}
	return 0;
#else
	return 0;
#endif
}

static __always_inline
int is_valid_lxc_src_ipv4(const struct iphdr *ip4 __maybe_unused)
{
#ifdef ENABLE_IPV4
	if (ip4->saddr == CONFIG(endpoint_ipv4).be32)
		return 1;

	/* Allow a saddr that is a Service VIP this node L2-announces. See the
	 * IPv6 path for the rationale and the enable-gate.
	 */
	if (CONFIG(enable_l2_announcements)) {
		struct l2_responder_v4_key l2key = {};

		l2key.ip4.be32 = ip4->saddr;
		l2key.ifindex = CONFIG(direct_routing_dev_ifindex);
		if (map_lookup_elem(&cilium_l2_responder_v4, &l2key))
			return 1;
	}
	return 0;
#else
	/* Can't send IPv4 if no IPv4 address is configured */
	return 0;
#endif
}
#else /* ENABLE_SIP_VERIFICATION */
static __always_inline
int is_valid_lxc_src_ip(struct ipv6hdr *ip6 __maybe_unused)
{
	return 1;
}

static __always_inline
int is_valid_lxc_src_ipv4(struct iphdr *ip4 __maybe_unused)
{
	return 1;
}
#endif /* ENABLE_SIP_VERIFICATION */
