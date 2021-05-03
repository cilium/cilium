/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

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
#include "proxy.h"

#define TEMPLATE_LXC_ID 0xffff
#define DHCP_CLIENT_ADDRESS 0x00000000
#define DHCP_SERVER_ADDRESS 0xffffffff
#define DHCP_CLIENT_PORT 17408 // is 68 in little endian
#define DHCP_SERVER_PORT 17152 // is 67 in little endian

#ifndef DISABLE_SIP_VERIFICATION
static __always_inline
int is_valid_lxc_src_ip(struct ipv6hdr *ip6 __maybe_unused)
{
#ifdef ENABLE_IPV6
	union v6addr valid = {};

	BPF_V6(valid, LXC_IP);

	return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
#else
	return 0;
#endif
}

static __always_inline
int is_valid_lxc_src_ipv4(const struct iphdr *ip4 __maybe_unused)
{
#ifdef ENABLE_IPV4
	return ip4->saddr == LXC_IPV4;
#else
	/* Can't send IPv4 if no IPv4 address is configured */
	return 0;
#endif
}
#else
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
#endif

/**
 * is_valid_dhcpv4_message validates whether packet is a valid
 * dhcp discover message
 * 0.0.0.0:68 -> 255.255.255.255:67
 */
static __always_inline
int is_valid_dhcpv4_message(struct __ctx_buff *ctx, int l4_off, struct iphdr *ip4)
{
	int ret;
	__be16 sport = 0;
	__be16 dport = 0;

	ret = l4_load_port(ctx, l4_off + UDP_SPORT_OFF, &sport);
	if (IS_ERR(ret))
		return ret;
	ret = l4_load_port(ctx, l4_off + UDP_DPORT_OFF, &dport);
	if (IS_ERR(ret))
		return ret;

	if (ip4->saddr == DHCP_CLIENT_ADDRESS && ip4->daddr == DHCP_SERVER_ADDRESS &&
	sport == DHCP_CLIENT_PORT && dport == DHCP_SERVER_PORT)
		return 1;

	return 0;
}

/**
 * ctx_redirect_to_proxy_hairpin redirects to the proxy by hairpining the
 * packet out the incoming interface
 */
static __always_inline int
ctx_redirect_to_proxy_hairpin(struct __ctx_buff *ctx, __be16 proxy_port)
{
	union macaddr host_mac = HOST_IFINDEX_MAC;
	union macaddr router_mac = NODE_MAC;
	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void *) (long) ctx->data;
	struct iphdr *ip4;
	int ret;

	ctx_store_meta(ctx, CB_PROXY_MAGIC,
		       MARK_MAGIC_TO_PROXY | (proxy_port << 16));
	bpf_barrier(); /* verifier workaround */

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	ret = ipv4_l3(ctx, ETH_HLEN, (__u8 *) &router_mac, (__u8 *) &host_mac, ip4);
	if (IS_ERR(ret))
		return ret;

	cilium_dbg(ctx, DBG_CAPTURE_PROXY_PRE, proxy_port, 0);

	/* Note that the actual __ctx_buff preparation for submitting the
	 * packet to the proxy will occur in a subsequent program via
	 * ctx_redirect_to_proxy_first().
	 */

	return redirect(HOST_IFINDEX, 0);
}

#endif /* __LIB_LXC_H_ */
