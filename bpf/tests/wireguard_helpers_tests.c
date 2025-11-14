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

PKTGEN("tc", "ctx_is_wireguard_success")
static __always_inline int
pktgen_wireguard_mock_check1(struct __ctx_buff *ctx) {
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one,
					  (__u8 *)mac_two,
					  v4_node_one,
					  v4_node_two,
					  bpf_htons(CONFIG(wg_port)),
					  bpf_htons(CONFIG(wg_port)));
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

CHECK("tc", "ctx_is_wireguard_success")
int check1(struct __ctx_buff *ctx)
{
	test_init();

	void *data, *data_end = NULL;
	struct iphdr *ipv4 = NULL;
	struct udphdr *udp = NULL;
	__be16 proto = bpf_htons(ETH_P_IP);

	/* Valid Wireguard packet. */
	wg_do_decrypt(ctx, proto);
	assert(ctx->mark == MARK_MAGIC_DECRYPT);

	ctx->mark = 0;

	/* Invalid protocol TCP. */
	assert(revalidate_data(ctx, &data, &data_end, &ipv4));
	ipv4->protocol = IPPROTO_TCP;
	wg_do_decrypt(ctx, proto);
	assert(ctx->mark == 0);

	/* Invalid L4 ports mismatching. */
	assert(revalidate_data(ctx, &data, &data_end, &ipv4));
	udp = (void *)ipv4 + sizeof(struct iphdr);
	assert((void *)udp + sizeof(struct udphdr) <= data_end)
	ipv4->protocol = IPPROTO_UDP;
	udp->source += 1;
	wg_do_decrypt(ctx, proto);
	assert(ctx->mark == 0);


	test_finish();
}

CHECK("tc", "ctx_mark_is_wireguard_success")
int check2(struct __ctx_buff *ctx)
{
	test_init();

	assert(!ctx_mark_is_wireguard(ctx));

	ctx->mark = MARK_MAGIC_ENCRYPT;

	assert(ctx_mark_is_wireguard(ctx));

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
