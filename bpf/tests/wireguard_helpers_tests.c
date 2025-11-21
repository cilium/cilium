// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_WIREGUARD 1
#define ENABLE_NODE_ENCRYPTION 1
#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define ETH_LEN 14

#define CLUSTER_IDENTITY 0x5555

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#include "node_config.h"
#include "lib/eps.h"
#include "lib/common.h"
#include "lib/wireguard.h"
#include "lib/ipv4.h"

#include "lib/ipcache.h"

ASSIGN_CONFIG(__u32, wg_ifindex, 42)
ASSIGN_CONFIG(__u16, wg_port, 51871)

static __always_inline int
ctx_is_wireguard_pktgen(struct __ctx_buff *ctx, bool is_ipv4) {
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	if (is_ipv4)
		l4 = pktgen__push_ipv4_udp_packet(&builder,
						  (__u8 *)mac_one,
						  (__u8 *)mac_two,
						  v4_node_one,
						  v4_node_two,
						  bpf_htons(CONFIG(wg_port)),
						  bpf_htons(CONFIG(wg_port)));
	else
		l4 = pktgen__push_ipv6_udp_packet(&builder,
						  (__u8 *)mac_one,
						  (__u8 *)mac_two,
						  (__u8 *)v6_node_one,
						  (__u8 *)v6_node_two,
						  bpf_htons(CONFIG(wg_port)),
						  bpf_htons(CONFIG(wg_port)));

	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

int ctx_is_wireguard_check(struct __ctx_buff *ctx, bool is_ipv4)
{
	test_init();

	void *data, *data_end = NULL;
	struct iphdr *ip4 = NULL;
	struct ipv6hdr *ip6 = NULL;
	struct udphdr *udp = NULL;
	int hdrlen = 0;
	__u8 protocol = 0;

	if (is_ipv4) {
		assert(revalidate_data(ctx, &data, &data_end, &ip4));
		protocol = ip4->protocol;
		hdrlen = ipv4_hdrlen(ip4);
		udp = (void *)ip4 + hdrlen;
	} else {
		assert(revalidate_data(ctx, &data, &data_end, &ip6));
		protocol = ip6->nexthdr;
		hdrlen = ipv6_hdrlen(ctx, &protocol);
		assert(hdrlen > 0);
		udp = (void *)ip6 + hdrlen;
	}

	assert((void *)udp + sizeof(struct udphdr) <= data_end)

	/* Valid Wireguard packet. */
	assert(ctx_is_wireguard(ctx, ETH_LEN + hdrlen, protocol, CLUSTER_IDENTITY));

	/* Invalid identity within CIDR. */
	assert(!ctx_is_wireguard(ctx, ETH_LEN + hdrlen, protocol, CIDR_IDENTITY_RANGE_START));

	/* Invalid protocol TCP. */
	assert(!ctx_is_wireguard(ctx, ETH_LEN + hdrlen, IPPROTO_TCP, CLUSTER_IDENTITY));

	/* Invalid L4 offset. */
	assert(!ctx_is_wireguard(ctx, ETH_LEN + hdrlen + 2, protocol, CLUSTER_IDENTITY));

	udp->source += 1;

	/* Invalid L4 ports mismatching. */
	assert(!ctx_is_wireguard(ctx, ETH_LEN + hdrlen, protocol, CLUSTER_IDENTITY));

	test_finish();
}

PKTGEN("tc", "ctx_is_wireguard_ipv4")
static __always_inline int
ctx_is_wireguard_ipv4_pktgen(struct __ctx_buff *ctx) {
	return ctx_is_wireguard_pktgen(ctx, true);
}

CHECK("tc", "ctx_is_wireguard_ipv4")
int ctx_is_wireguard_ipv4_check(struct __ctx_buff *ctx)
{
	return ctx_is_wireguard_check(ctx, true);
}

PKTGEN("tc", "ctx_is_wireguard_ipv6")
static __always_inline int
ctx_is_wireguard_ipv6_pktgen(struct __ctx_buff *ctx) {
	return ctx_is_wireguard_pktgen(ctx, false);
}

CHECK("tc", "ctx_is_wireguard_ipv6")
int ctx_is_wireguard_ipv6_check(struct __ctx_buff *ctx)
{
	return ctx_is_wireguard_check(ctx, false);
}

CHECK("tc", "ctx_is_encrypt_success")
int check2(struct __ctx_buff *ctx)
{
	test_init();

	assert(!ctx_is_encrypt(ctx));

	ctx->mark = MARK_MAGIC_ENCRYPT;

	assert(ctx_is_encrypt(ctx));

	test_finish();
}

CHECK("tc", "ctx_is_decrypt_success")
int check3(struct __ctx_buff *ctx)
{
	test_init();

	assert(!ctx_is_decrypt(ctx));

	ctx->mark = MARK_MAGIC_DECRYPT;

	assert(ctx_is_decrypt(ctx));

	test_finish();
}

PKTGEN("tc", "wireguard_icmpv6_na_skip")
int wireguard_icmpv6_na_skip_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmp6hdr *icmp6;

	pktgen__init(&builder, ctx);

	icmp6 = pktgen__push_ipv6_icmp6_packet(&builder,
					       (__u8 *)mac_one,
					       (__u8 *)mac_two,
					       (__u8 *)v6_pod_one,
					       (__u8 *)v6_pod_two,
					       ICMPV6_NA_MSG);
	if (!icmp6)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

CHECK("tc", "wireguard_icmpv6_na_skip")
int wireguard_icmpv6_na_skip_check(struct __ctx_buff *ctx)
{
	int ret_val;

	ipcache_v6_add_entry((union v6addr *)v6_pod_one, 0, 123, 0, 1);
	ipcache_v6_add_entry((union v6addr *)v6_pod_two, 0, 456, 0, 1);

	test_init();

	ret_val = wg_maybe_redirect_to_encrypt(ctx, bpf_htons(ETH_P_IPV6), 123);
	assert(ret_val == CTX_ACT_OK);

	test_finish();
}
