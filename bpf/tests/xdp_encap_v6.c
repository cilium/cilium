// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Regression test for the XDP ctx_set_encap_info6() return value.
 *
 * XDP does not implement encapsulation towards an IPv6 tunnel endpoint. It
 * used to signal that by returning 0, but 0 does not satisfy IS_ERR(), so
 * callers treated the packet as successfully encapsulated:
 *
 *   tail_nodeport_nat_egress_ipv6() (bpf/lib/nodeport.h)
 *     ret = nodeport_add_tunnel_encap(...);   // -> 0
 *     if (IS_ERR(ret)) goto drop_err;         // not taken, 0 is not < 0
 *     if (ret == CTX_ACT_REDIRECT && oif)     // not taken
 *             return ctx_redirect(ctx, oif, 0);
 *     goto fib_ipv4;                          // AF_INET FIB lookup over an
 *                                             // unencapsulated IPv6 packet
 *
 * Assert instead that the unimplemented case is reported as an error and
 * that the packet is left untouched.
 */

#include <bpf/ctx/xdp.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_IPV6

/* Defining ENCAP_IFINDEX is what pulls in HAVE_ENCAP, see bpf/lib/common.h. */
#define ENCAP_IFINDEX		42
#define TUNNEL_MODE

#include "lib/common.h"
#include "lib/overloadable.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define SEC_IDENTITY	0x1234

/* Size of the packet produced by the PKTGEN below:
 * eth(14) + ipv4(20) + tcp(20) + payload(20) = 74.
 */
#define INNER_LEN	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

/* Outer (underlay) IPv6 tunnel endpoint. */
static volatile const union v6addr tunnel_ep = { .addr = v6_node_one_addr };

PKTGEN("xdp", "xdp_encap_v6_unsupported")
int xdp_encap_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
					  SRC_IP, DST_IP,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("xdp", "xdp_encap_v6_unsupported")
int xdp_encap_v6_setup(struct __ctx_buff *ctx)
{
	union v6addr ep = tunnel_ep;

	/* The harness prepends the return value to the packet data handed to
	 * the CHECK program below.
	 */
	return ctx_set_encap_info6(ctx, &ep, SEC_IDENTITY, NULL, 0);
}

CHECK("xdp", "xdp_encap_v6_unsupported")
int xdp_encap_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *eth;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	/* Regression: this used to be 0, which is not IS_ERR() and which is
	 * also XDP_ABORTED where the value reaches an XDP entrypoint.
	 */
	if (*status_code == 0)
		test_fatal("returned 0: callers will forward the packet unencapsulated");

	assert(*status_code == (__u32)DROP_INVALID);

	/* Nothing must have been prepended to the packet. */
	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("packet was modified, outer proto is 0x%x",
			   bpf_ntohs(eth->h_proto));

	if ((void *)eth + INNER_LEN != data_end)
		test_fatal("packet length changed");

	test_finish();
}
