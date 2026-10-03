// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define TUNNEL_MODE		1
#define HAVE_ENCAP		1
#define ENABLE_BPF_GENEVE	1
#define ENCAP_IFINDEX		42
#define SKIP_GENEVE_HANDLING	1

#include "lib/common.h"
#include "lib/tailcall.h"

static __u32 intercepted_slot;
static struct bpf_tunnel_key intercepted_key;

static __always_inline int
mock_geneve_tailcall(struct __ctx_buff *ctx, __u32 slot, __s8 *ext_err __maybe_unused)
{
	intercepted_slot = slot;
	if (slot == CILIUM_CALL_GENEVE_ENCAP6)
		ctx_get_tunnel_key(ctx, &intercepted_key, sizeof(intercepted_key), BPF_F_TUNINFO_IPV6);
	else
		ctx_get_tunnel_key(ctx, &intercepted_key, sizeof(intercepted_key), 0);
	return 0;
}

#undef tail_call_internal
#define tail_call_internal(ctx, slot, ext_err) mock_geneve_tailcall(ctx, slot, ext_err)

#include "lib/encap.h"

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define TUNNEL_DST_V4	v4_node_two
#define TEST_SECLABEL	0x112233
#define TEST_DSTID	0x445566

static volatile const union v6addr tunnel_dst_v6 = { .addr = v6_node_two_addr };

PKTGEN("tc", "geneve_dispatch_v4")
int bpf_geneve_dispatch_v4_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_dispatch_v4")
int bpf_geneve_dispatch_v4_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info info = {};
	struct trace_ctx trace = {};

	info.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4;
	info.flag_ipv6_tunnel_ep = false;

	return __encap_and_redirect_with_nodeid(ctx, &info, TEST_SECLABEL,
						TEST_DSTID, NOT_VTEP_DST,
						&trace, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_dispatch_v4")
int bpf_geneve_dispatch_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != 0)
		test_fatal("dispatch returned error: %d", *status_code);

	if (intercepted_slot != CILIUM_CALL_GENEVE_ENCAP4)
		test_fatal("wrong tail call slot dispatched: %d expected %d",
			   intercepted_slot, CILIUM_CALL_GENEVE_ENCAP4);

	if (intercepted_key.tunnel_id != TEST_SECLABEL)
		test_fatal("dispatched tunnel_id mismatch: got 0x%lx expected 0x%lx",
			   (__u64)intercepted_key.tunnel_id, (__u64)TEST_SECLABEL);

	if (intercepted_key.local_ipv4 != bpf_ntohl(TUNNEL_DST_V4))
		test_fatal("dispatched remote_ipv4 (dst) mismatch: got 0x%lx expected 0x%lx",
			   (__u64)intercepted_key.local_ipv4, (__u64)bpf_ntohl(TUNNEL_DST_V4));

	test_finish();
}

PKTGEN("tc", "geneve_dispatch_v6")
int bpf_geneve_dispatch_v6_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_dispatch_v6")
int bpf_geneve_dispatch_v6_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info info = {};
	struct trace_ctx trace = {};

	ipv6_addr_copy(&info.tunnel_endpoint.ip6, (const union v6addr *)&tunnel_dst_v6);
	info.flag_ipv6_tunnel_ep = true;

	return __encap_and_redirect_with_nodeid(ctx, &info, TEST_SECLABEL,
						TEST_DSTID, NOT_VTEP_DST,
						&trace, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_dispatch_v6")
int bpf_geneve_dispatch_v6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (*status_code != 0)
		test_fatal("dispatch returned error: %d", *status_code);

	if (intercepted_slot != CILIUM_CALL_GENEVE_ENCAP6)
		test_fatal("wrong tail call slot dispatched: %d expected %d",
			   intercepted_slot, CILIUM_CALL_GENEVE_ENCAP6);

	if (intercepted_key.tunnel_id != TEST_SECLABEL)
		test_fatal("dispatched tunnel_id mismatch: got 0x%lx expected 0x%lx",
			   (__u64)intercepted_key.tunnel_id, (__u64)TEST_SECLABEL);

	if (intercepted_key.local_ipv6[0] != tunnel_dst_v6.p1 ||
	    intercepted_key.local_ipv6[1] != tunnel_dst_v6.p2 ||
	    intercepted_key.local_ipv6[2] != tunnel_dst_v6.p3 ||
	    intercepted_key.local_ipv6[3] != tunnel_dst_v6.p4)
		test_fatal("dispatched remote_ipv6 (dst) mismatch");

	test_finish();
}
