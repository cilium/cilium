// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_NODEPORT		1
#define ENABLE_DSR		1
#define DSR_ENCAP_IPIP		2
#define DSR_ENCAP_MODE		DSR_ENCAP_IPIP
#define ENABLE_HEALTH_CHECK	1

#define DISABLE_LOOPBACK_LB

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)

#define ENCAP_IFINDEX		25

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		__bpf_htons(80)

#define BACKEND_IP		v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define ENCAP4_IFINDEX		42
#define ENCAP6_IFINDEX		42

#define SOCKET_COOKIE		1

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *backend_mac = mac_two;

#define get_socket_cookie mock_get_socket_cookie

__u64 mock_get_socket_cookie(const struct __sk_buff *ctx __maybe_unused)
{
	return SOCKET_COOKIE;
}

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex == ENCAP4_IFINDEX)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

#define skb_set_tunnel_key mock_skb_set_tunnel_key

int mock_skb_set_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    __maybe_unused const struct bpf_tunnel_key *from,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags)
{
	if (from->tunnel_id != 0)
		return -1;
	if (from->local_ipv4 != 0)
		return -2;
	if (from->remote_ipv4 != bpf_ntohl(BACKEND_IP))
		return -3;
	return 0;
}

#define SECCTX_FROM_IPCACHE 1

#include "bpf_host.c"

#define TO_NETDEV	0

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

/* Test that a health-check request to a remote backend is IPIP-encapsulated. */
PKTGEN("tc", "l4lb_health_check_host")
int l4lb_health_check_host_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)backend_mac,
					  CLIENT_IP, FRONTEND_IP,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "l4lb_health_check_host")
int l4lb_health_check_host_setup(struct __ctx_buff *ctx)
{
	__sock_cookie key = SOCKET_COOKIE;
	struct lb4_health value = {
		.peer = {
			.address = BACKEND_IP,
		}
	};

	map_update_elem(&LB4_HEALTH_MAP, &key, &value, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "l4lb_health_check_host")
int l4lb_health_check_host_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the client MAC")
	if (memcmp(l2->h_dest, (__u8 *)backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the backend MAC")

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != FRONTEND_IP)
		test_fatal("dst IP has changed");

	if (l3->check != bpf_htons(0x402))
		test_fatal("L3 checksum is invalid: %d", bpf_htons(l3->check));

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != FRONTEND_PORT)
		test_fatal("dst port has changed");

	test_finish();
}
