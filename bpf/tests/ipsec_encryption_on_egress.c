// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"
#include "node_config.h"
#include "lib/encrypt.h"

/* we need to include bpf_host.c later for mocking of the IPsec hook to work
 * but both node_config.h and bpf_host.c define EVENT_SOURCE explicitly.
 * therefore, undef EVENT_SOURCE so we get all the defines from node_config.h
 * except this, and bpf_host.c can define it.
 */
#undef EVENT_SOURCE

#define ENABLE_ROUTING
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_IPSEC
#define IPV4_LOOPBACK 0

#define TO_NETDEV 0

bool hook_reached;

int mock_ipsec_maybe_redirect_to_encrypt(__maybe_unused struct __ctx_buff *ctx,
					 __maybe_unused __be16 proto)
{
	hook_reached = true;
	return CTX_ACT_REDIRECT;
}

#define ipsec_maybe_redirect_to_encrypt mock_ipsec_maybe_redirect_to_encrypt

#include "bpf_host.c"

/* setup map for tailcall to egress native device program */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
	},
};

PKTGEN("tc", "ipsec_encryption_on_egress")
int ipsec_encryption_on_egress_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);

	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;
	l3->saddr = v4_pod_one;
	l3->daddr = v4_pod_two;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipsec_encryption_on_egress")
int ipsec_encryption_on_egress_setup(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

/* this is a very basic test which ensures any packets leaving on a native
 * device is subjected to possible IPsec encryption when IPsec is enabled.
 *
 * a more specific test exists for testing the functionality of the hook itself
 * therefore, if this integration test fails, the datapath is no longer reliably
 * IPsec encrypting packets leaving the host.
 */
CHECK("tc", "ipsec_encryption_on_egress")
int ipsec_encryption_on_egress_check(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();
	assert(hook_reached);
	test_finish();
}
