// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_WIREGUARD 1
#define ENABLE_IPV4 1
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
					  bpf_htons(WG_PORT),
					  bpf_htons(WG_PORT));
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
	int l4_off = 0;
	__u8 protocol = 0;

	assert(revalidate_data(ctx, &data, &data_end, &ipv4));

	udp = (void *)ipv4 + sizeof(struct iphdr);

	assert((void *)udp + sizeof(struct udphdr) <= data_end)

	l4_off = ETH_LEN + ipv4_hdrlen(ipv4);
	protocol = ipv4->protocol;

	/* Valid Wireguard packet. */
	assert(ctx_is_wireguard(ctx, l4_off, protocol, CLUSTER_IDENTITY));

	/* Invalid identity within CIDR. */
	assert(!ctx_is_wireguard(ctx, l4_off, protocol, CIDR_IDENTITY_RANGE_START));

	/* Invalid protocol TCP. */
	assert(!ctx_is_wireguard(ctx, l4_off, IPPROTO_TCP, CLUSTER_IDENTITY));

	/* Invalid L4 offset. */
	assert(!ctx_is_wireguard(ctx, l4_off + 2, protocol, CLUSTER_IDENTITY));

	udp->source += 1;

	/* Invalid L4 ports mismatching. */
	assert(!ctx_is_wireguard(ctx, l4_off, protocol, CLUSTER_IDENTITY));

	test_finish();
}

CHECK("tc", "ctx_mark_is_wireguard_success")
int check2(struct __ctx_buff *ctx)
{
	test_init();

	assert(!ctx_mark_is_wireguard(ctx));

	ctx->mark = MARK_MAGIC_WG_ENCRYPTED;

	assert(ctx_mark_is_wireguard(ctx));

	test_finish();
}
