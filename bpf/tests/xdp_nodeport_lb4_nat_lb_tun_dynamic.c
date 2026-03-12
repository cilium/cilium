// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include "common.h"
#include "pktgen.h"

/* This test confirms the XDP/tunnel mode path for nodeport load balanced packets
 * dynamically resolves the source IP used for manual header injection.
 */

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_HOST_ROUTING
#define TUNNEL_MODE
#define ENABLE_NODEPORT_ACCELERATION

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP_REMOTE	v4_svc_two
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one
#define IPV4_DIRECT_ROUTING	LB_IP
#define TUNNEL_SOURCE		0xDEADBEEF
#define REMOTE_TUNNEL_ENDPOINT	v4_node_two

#define BACKEND_IP_REMOTE	v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define DEFAULT_IFACE		24
#define ENCAP_IFINDEX		42

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *lb_mac = mac_host;

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(__maybe_unused struct __ctx_buff * volatile ctx,
		     const struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	/* Verifier doesn't know that params is not NULL when verifying this
	 * function separately (see btf_prepare_func_args in kernel/bpf/btf.c).
	 * There is no appropriate EINVAL-like error code in this helper, so
	 * return some arbitrary error.
	 */
	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;

	return BPF_FIB_LKUP_RET_SUCCESS;
}

/*
 * This is the entire dependency chain required to import bpf/lib/fib.h for
 * mocking below
 */
#define ACTION_UNKNOWN_ICMP6_NS	CTX_ACT_OK
#include "../node_config.h"
#include "../include/bpf/config/node.h"
#include "../include/bpf/config/global.h"
#include "../lib/fib.h"

/* mock the fib_lookup_src_v4 library function to always return our
 * test SNAT ip.
 */
#define fib_lookup_src_v4 mock_fib_lookup_src_v4

static __always_inline int
mock_fib_lookup_src_v4(struct __ctx_buff *ctx __maybe_unused, __be32 *src,
		       const __be32 dst __maybe_unused)
{
	*src = TUNNEL_SOURCE;
	return BPF_FIB_LKUP_RET_SUCCESS;
}

#include "lib/bpf_xdp.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)
ASSIGN_CONFIG(bool, enable_nodeport_source_lookup, true)
ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_VXLAN)
ASSIGN_CONFIG(__u16, tunnel_port, 8472)

/* Set port ranges to have deterministic source port selection */
#include "nodeport_defaults.h"

/* Test that an XDP nodeport load balanced packet has its outer source
 * ip dynamically resolved.
 */
PKTGEN("xdp", "xdp_nodeport_lb4_nat_lb_tun_dynamic")
int xdp_nodeport_lb4_nat_lb_tun_dynamic_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)lb_mac,
					  CLIENT_IP, FRONTEND_IP_REMOTE,
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

SETUP("xdp", "xdp_nodeport_lb4_nat_lb_tun_dynamic")
int xdp_nodeport_lb4_nat_lb_tun_dynamic_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP_REMOTE, FRONTEND_PORT, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP_REMOTE, FRONTEND_PORT, 1, 124,
			  BACKEND_IP_REMOTE, BACKEND_PORT, IPPROTO_TCP, 0);

	ipcache_v4_add_entry(BACKEND_IP_REMOTE, 0, 112233, REMOTE_TUNNEL_ENDPOINT, 0);

	return xdp_receive_packet(ctx);
}

CHECK("xdp", "xdp_nodeport_lb4_nat_lb_tun_dynamic")
int xdp_nodeport_lb4_nat_lb_tun_dynamic_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_TX);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != TUNNEL_SOURCE)
		test_fatal("tunnel source IP was not dynamically resolved");

	if (l3->daddr != REMOTE_TUNNEL_ENDPOINT)
		test_fatal("expected tunnel endpoint destination");

	if (l3->check != bpf_htons(0xc8e0))
		test_fatal("L3 checksum is invalid: %x", bpf_htons(l3->check));

	if (l4->dest != bpf_htons(CONFIG(tunnel_port)))
		test_fatal("dst port must be vxlan");

	test_finish();
}
