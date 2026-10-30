// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define ENABLE_NODE_ENCRYPTION 1
#define ENABLE_IPV4 1
#define ENABLE_IPV6 1

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
ASSIGN_CONFIG(bool, enable_wireguard, true)

CHECK(PROG_TYPE, "ctx_is_encrypt_success")
int check2(struct __ctx_buff *ctx)
{
	test_init();

	assert(!ctx_is_encrypt(ctx));

	ctx->mark = MARK_MAGIC_ENCRYPT;

	assert(ctx_is_encrypt(ctx));

	test_finish();
}

CHECK(PROG_TYPE, "ctx_is_decrypt_success")
int check3(struct __ctx_buff *ctx)
{
	test_init();

	assert(!ctx_is_decrypt(ctx));

	ctx->mark = MARK_MAGIC_DECRYPT;

	assert(ctx_is_decrypt(ctx));

	test_finish();
}

PKTGEN(PROG_TYPE, "wireguard_icmpv6_na_skip")
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

CHECK(PROG_TYPE, "wireguard_icmpv6_na_skip")
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
