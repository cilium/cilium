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
#include "proxy.h"
#include "proxy_hairpin.h"

DECLARE_CONFIG(bool, enable_sip_verification,
	       "Enable source IP verification for endpoint egress")

static __always_inline
int is_valid_lxc_src_ip(struct ipv6hdr *ip6 __maybe_unused)
{
	if (!CONFIG(enable_sip_verification))
		return 1;

#ifdef ENABLE_IPV6
	union v6addr valid = CONFIG(endpoint_ipv6);

	return ipv6_addr_equals((union v6addr *)&ip6->saddr, &valid);
#else
	return 0;
#endif
}

static __always_inline
int is_valid_lxc_src_ipv4(const struct iphdr *ip4 __maybe_unused)
{
	if (!CONFIG(enable_sip_verification))
		return 1;

#ifdef ENABLE_IPV4
	return ip4->saddr == CONFIG(endpoint_ipv4).be32;
#else
	/* Can't send IPv4 if no IPv4 address is configured */
	return 0;
#endif
}
