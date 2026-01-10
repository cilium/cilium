// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "lib/ipv6_core.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_DSR
#define DSR_ENCAP_IPIP		2
#define DSR_ENCAP_MODE		DSR_ENCAP_IPIP

#define ENCAP6_IFINDEX		42

/* Skip ingress policy checks */
#define USE_BPF_PROG_FOR_INGRESS_POLICY

#define CLIENT_IP		{ .addr = { 0x1 } }
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		{ .addr = { 0x2 } }
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			{ .addr = { 0x5 } }
#define IPV6_DIRECT_ROUTING	LB_IP

#define BACKEND_IP		{ .addr = { 0x3 } }
#define BACKEND_PORT		__bpf_htons(8080)

#define fib_lookup mock_fib_lookup

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;
static volatile const __u8 *remote_backend_mac = mac_five;

long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	union v6addr backend_ip = BACKEND_IP;

	params->ifindex = 0;

	if (params->ipv6_dst[0] == backend_ip.p1 &&
	    params->ipv6_dst[1] == backend_ip.p2 &&
	    params->ipv6_dst[2] == backend_ip.p3 &&
	    params->ipv6_dst[3] == backend_ip.p4) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)remote_backend_mac, ETH_ALEN);
	} else {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
	}

	return BPF_FIB_LKUP_RET_SUCCESS;
}

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __ctx_buff *ctx __maybe_unused, int ifindex __maybe_unused,
		  __u32 flags __maybe_unused)
{
	if (ifindex != ENCAP6_IFINDEX)
		return CTX_ACT_DROP;

	return CTX_ACT_REDIRECT;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_tunnel_key));
	__uint(max_entries, 1);
} tunnel_key_map __section_maps_btf;

#define skb_set_tunnel_key mock_skb_set_tunnel_key
int mock_skb_set_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    __maybe_unused const struct bpf_tunnel_key *from,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags)
{
	__u32 map_key = 0;
	struct bpf_tunnel_key *mock_key = map_lookup_elem(&tunnel_key_map, &map_key);

	if (mock_key)
		memcpy(mock_key, from, sizeof(*from));

	return 0;
}

#include "lib/bpf_host.h"

#include "lib/ipcache.h"
#include "lib/lb.h"

/* Test that a SVC request that is LBed to a DSR remote backend
 * - is IPIP encapsulated via tunnel key,
 * - keeps the inner destination as the service IP,
 * - gets redirected back out by TC
 */
PKTGEN("tc", "tc_nodeport_dsr_ipip6_fwd")
int nodeport_dsr_ipip6_fwd_pktgen(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IP;
	union v6addr client_ip = CLIENT_IP;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  (__u8 *)&client_ip, (__u8 *)&frontend_ip,
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

SETUP("tc", "tc_nodeport_dsr_ipip6_fwd")
int nodeport_dsr_ipip6_fwd_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IP;
	union v6addr backend_ip = BACKEND_IP;
	__u16 revnat_id = 1;

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&frontend_ip, FRONTEND_PORT, 1, 124,
			  &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v6_add_entry(&backend_ip, 0, 112233, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_nodeport_dsr_ipip6_fwd")
int nodeport_dsr_ipip6_fwd_check(__maybe_unused const struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IP;
	union v6addr backend_ip = BACKEND_IP;
	union v6addr client_ip = CLIENT_IP;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	struct bpf_tunnel_key *tunnel_key;
	__u32 key = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("src IP has changed");
	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &frontend_ip))
		test_fatal("dst IP has changed");
	if (l3->nexthdr != IPPROTO_TCP)
		test_fatal("l3 header doesn't indicate TCP payload");
	if (l3->payload_len != bpf_htons(sizeof(struct tcphdr) + sizeof(default_data)))
		test_fatal("payload_len changed unexpectedly");

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");
	if (l4->dest != FRONTEND_PORT)
		test_fatal("dst port has changed");
	if (l4->check != bpf_htons(0x2dbc))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	tunnel_key = map_lookup_elem(&tunnel_key_map, &key);
	if (!tunnel_key)
		test_fatal("no tunnel key set");
	if (tunnel_key->remote_ipv6[0] != backend_ip.p1 ||
	    tunnel_key->remote_ipv6[1] != backend_ip.p2 ||
	    tunnel_key->remote_ipv6[2] != backend_ip.p3 ||
	    tunnel_key->remote_ipv6[3] != backend_ip.p4)
		test_fatal("tunnel remote IP is not correct");
	if (tunnel_key->tunnel_id != 0)
		test_fatal("tunnel id is not correct");
	if (tunnel_key->tunnel_ttl != IPDEFTTL)
		test_fatal("tunnel ttl is not correct");

	test_finish();
}
