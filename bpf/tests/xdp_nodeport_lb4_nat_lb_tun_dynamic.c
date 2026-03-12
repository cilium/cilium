// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

/* This test confirms the XDP/tunnel mode path for nodeport load balanced packets
 * dynamically resolves the source IP used for manual header injection.
 */

/* Enable code paths under test */
#define ENABLE_IPV4 1
#define ENABLE_NODEPORT 1
#define ENABLE_HOST_ROUTING 1
#define TUNNEL_MODE 1
#define ENABLE_NODEPORT_ACCELERATION 1

#define FRONTEND_IP_REMOTE	v4_svc_two
#define FRONTEND_PORT		tcp_svc_one

#define TUNNEL_SOURCE		0xDEADBEEF
#define REMOTE_TUNNEL_ENDPOINT	v4_node_two

#define BACKEND_IP_REMOTE	v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define DEFAULT_IFACE		24
#define ENCAP_IFINDEX		42

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(__maybe_unused struct __ctx_buff * volatile ctx,
		     struct bpf_fib_lookup *params, __maybe_unused int plen,
		     __maybe_unused __u32 flags)
{
	/* Verifier doesn't know that params is not NULL when verifying this
	 * function separately (see btf_prepare_func_args in kernel/bpf/btf.c).
	 * There is no appropriate EINVAL-like error code in this helper, so
	 * return some arbitrary error.
	 */
	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;

	params->ipv4_src = TUNNEL_SOURCE;
	params->ifindex = 0xA;

	return BPF_FIB_LKUP_RET_SUCCESS;
}

#include "lib/bpf_xdp.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u32, interface_ifindex, DEFAULT_IFACE)
ASSIGN_CONFIG(bool, supports_fib_lookup_src, true)
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

	pktgen__init(&builder, ctx);

	BUF_DECL(XDP_NODEPORT_TUN_SNAT_DYN_V4_PRE, xdp_nodeport_lb4_nat_lb_tun_dynamic_pre);

	BUILDER_PUSH_BUF(builder, XDP_NODEPORT_TUN_SNAT_DYN_V4_PRE);

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
int xdp_nodeport_lb4_nat_lb_tun_dynamic_check(const struct __ctx_buff *ctx)
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

	BUF_DECL(XDP_NODEPORT_TUN_SNAT_DYN_V4_POST, xdp_nodeport_lb4_nat_lb_tun_dynamic_post);
	ASSERT_CTX_BUF_OFF("dynamic_tun_snat_ok", "Ether", ctx, sizeof(__u32),
			   XDP_NODEPORT_TUN_SNAT_DYN_V4_POST,
			   sizeof(struct ethhdr) + sizeof(struct iphdr));

	test_finish();
}
