// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_L7_LB
#define ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)
#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one
#define IPV4_DIRECT_ROUTING	LB_IP

#define ENCAP_IFINDEX		0

#define PROXY_PORT		10000

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;

/* Track ctx_redirect calls */
static volatile __u32 redirect_ifindex;

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(const __maybe_unused void *ctx,
		     const struct bpf_fib_lookup *params __maybe_unused,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	return BPF_FIB_LKUP_RET_NO_NEIGH;
}

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex, __u32 flags __maybe_unused)
{
	redirect_ifindex = (__u32)ifindex;
	return CTX_ACT_REDIRECT;
}

#include "bpf_host.c"

#include "lib/lb.h"
#include "lib/ipcache.h"
#include "lib/clear.h"

ASSIGN_CONFIG(__u32, cilium_net_ifindex, HOST_IFINDEX)

/* Enable redirect via cilium_net to test hairpinning when cil_from_netdev
 * is attached to a bridge device.
 */
ASSIGN_CONFIG(bool, proxy_redirect_via_cilium_net, true)

#define FROM_NETDEV	0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
	},
};

/* Test 1: IPv4 L7 LB on bridge device. Ensure packets is hairpinned via cilium_net. */
PKTGEN("tc", "l7_lb_hairpin_v4")
int l7_lb_hairpin_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "l7_lb_hairpin_v4")
int l7_lb_hairpin_v4_setup(struct __ctx_buff *ctx)
{
	clear_map(&LB4_SERVICES_MAP_V2);
	clear_map(&LB4_REVERSE_NAT_MAP);

	lb_v4_add_l7_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, PROXY_PORT);

	ipcache_v4_add_entry(FRONTEND_IP, 0, 112233, 0, 0);

	redirect_ifindex = 0;

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "l7_lb_hairpin_v4")
int l7_lb_hairpin_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	if (redirect_ifindex != CONFIG(cilium_net_ifindex))
		test_fatal("expected redirect to cilium_net (ifindex %d), got ifindex %d",
			   CONFIG(cilium_net_ifindex), redirect_ifindex);

	test_finish();
}

/* Test 1: IPv6 L7 LB on bridge device. Ensure packets is hairpinned via cilium_net. */
PKTGEN("tc", "l7_lb_hairpin_v6")
int l7_lb_hairpin_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)v6_ext_node_one,
					  (__u8 *)v6_svc_one,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "l7_lb_hairpin_v6")
int l7_lb_hairpin_v6_setup(struct __ctx_buff *ctx)
{
	clear_map(&LB6_SERVICES_MAP_V2);
	clear_map(&LB6_REVERSE_NAT_MAP);

	lb_v6_add_l7_service((union v6addr *)v6_svc_one, FRONTEND_PORT,
			     IPPROTO_TCP, 1, PROXY_PORT);

	ipcache_v6_add_entry((union v6addr *)v6_svc_one, 0, 112233, 0, 0);

	redirect_ifindex = 0;

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "l7_lb_hairpin_v6")
int l7_lb_hairpin_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	if (redirect_ifindex != CONFIG(cilium_net_ifindex))
		test_fatal("expected redirect to cilium_net (ifindex %d), got ifindex %d",
			   CONFIG(cilium_net_ifindex), redirect_ifindex);

	test_finish();
}
