/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

/* We always assume we have BPF Host Routing enabled */
#define ENABLE_HOST_ROUTING 1

/* Define an endpoint ID that we'll use as index into policy maps. */
#define TEST_LXC_ID_LOCAL 233

/* Define host and LXC interface index */
#define TEST_HOST_IFACE 24
#define TEST_LXC_IFACE 25

/* Define mac addresses we expect to see on redirected packet */
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *ep_mac = mac_four;

/* Counters to record helper usage across tests */
enum {
	RECORD_TAILCALL = 0,
	RECORD_REDIRECT,
	RECORD_REDIRECT_PEER,
	RECORD__MAX
};

static unsigned int num_calls[RECORD__MAX] = {};

/* Mocked out BPF helpers that we're intending to test usage of. */
int mock_ctx_redirect(const struct __ctx_buff *ctx __maybe_unused,
		      int ifindex __maybe_unused,
		      __u32 flags __maybe_unused)
{
	num_calls[RECORD_REDIRECT]++;
	return CTX_ACT_REDIRECT;
}

int mock_ctx_redirect_peer(const struct __ctx_buff *ctx __maybe_unused,
			   int ifindex __maybe_unused,
			   __u32 flags __maybe_unused)
{
	num_calls[RECORD_REDIRECT_PEER]++;
	return CTX_ACT_REDIRECT;
}

int mock_tail_policy(struct __ctx_buff *ctx); /* Defined below bpf_host inclusion */

__section_entry
int mock_handle_policy(struct __ctx_buff *ctx)
{
	num_calls[RECORD_TAILCALL]++;

	/* If we've invoked a policy tailcall exactly once, we can proceed to
	 * a redirect. In the case of bpf_host, we need to call our mock
	 * policy handling, which will call redirect_ep().
	 */
	if (num_calls[RECORD_TAILCALL] == 1)
		return mock_tail_policy(ctx);

	return CTX_ACT_DROP;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[TEST_LXC_ID_LOCAL] = &mock_handle_policy,
	},
};

static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused,
		       __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

#define tail_call_dynamic mock_tail_call_dynamic
#define ctx_redirect mock_ctx_redirect
#define ctx_redirect_peer mock_ctx_redirect_peer

/* Load the appropriate BPF programs. */
#include "lib/bpf_host.h"

/* Mocked out policy function so we can test redirect_ep(). This is needed
 * because the policy logic is in bpf_lxc and we can't include that here.
 * But, the aim of this test is to exercise the redirect_ep() logic so this
 * seems OK.
 */
int mock_tail_policy(struct __ctx_buff *ctx)
{
	bool do_redirect = ctx_load_meta(ctx, CB_DELIVERY_REDIRECT);
	bool from_host = ctx_load_and_clear_meta(ctx, CB_FROM_HOST);
	bool from_tunnel = false;

	/* We should always be from_host here. */
	if (do_redirect && from_host)
		return redirect_ep(ctx, CONFIG(interface_ifindex),
				   should_redirect_peer(from_host),
				   from_tunnel);

	/* Failure path */
	return CTX_ACT_DROP;
}

/* Set our host interface index */
ASSIGN_CONFIG(__u32, interface_ifindex, TEST_HOST_IFACE)

/* Deal with testing netkit or veth. */
#ifdef __CONFIG_ENABLE_NETKIT
#define TEST_DRIVER_NAME "netkit"
ASSIGN_CONFIG(bool, enable_netkit, true)
#else
#define TEST_DRIVER_NAME "veth"
ASSIGN_CONFIG(bool, enable_netkit, false)
#endif

/* Source identity so we can validate skb mark. */
#define TEST_SRC_IDENTITY 0xCAFE
#if !defined(__CONFIG_ENABLE_NETKIT) && defined(USE_BPF_PROG_FOR_INGRESS_POLICY)
#define TEST_SKB_MARK (__u32)((TEST_SRC_IDENTITY << 16) | MARK_MAGIC_IDENTITY)
#else
#define TEST_SKB_MARK (__u32)0x0
#endif

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"

#ifdef ENABLE_IPV4

/* Setup for this test:
 * +--------External--------+    +----------Pod 1---------+
 * | v4_ext_one:high-port   | -> | v4_pod_one:tcp_svc_one |
 * +------------------------+    +------------------------+
 */
PKTGEN("tc", "tc_redirect_host_ipv4")
int tc_redirect_host_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(REDIRECT_HOST_IPV4_PRE, tc_redirect_host_ipv4_pre);
	BUILDER_PUSH_BUF(builder, REDIRECT_HOST_IPV4_PRE);

	pktgen__finish(&builder);

	return 0;
}

/* Test that sending a packet from a pod to its own service gets source nat-ed
 * and that it is forwarded to the correct veth.
 */
SETUP("tc", "tc_redirect_host_ipv4")
int tc_redirect_host_ipv4_setup(struct __ctx_buff *ctx)
{
	/* Add an IPCache entry for pod 1 */
	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);

	/* Add endpoint for local LXC */
	endpoint_v4_add_entry(v4_pod_one, TEST_LXC_IFACE, TEST_LXC_ID_LOCAL, 0, 0, 0,
			      (const __u8 *)ep_mac, (const __u8 *)node_mac);

	/* Add source identity to test mark */
	ipcache_v4_add_entry(v4_ext_one, 0, TEST_SRC_IDENTITY, 0, 0);

	return host_send_packet(ctx);
}

CHECK("tc", "tc_redirect_host_ipv4")
int tc_redirect_host_ipv4_check(__maybe_unused const struct __ctx_buff *ctx)
{
#ifdef __CONFIG_ENABLE_NETKIT
	const unsigned int expected[RECORD__MAX] = {1, 1, 0};
#elif !defined(__CONFIG_ENABLE_NETKIT) && defined(USE_BPF_PROG_FOR_INGRESS_POLICY)
	const unsigned int expected[RECORD__MAX] = {0, 1, 0};
#else
	const unsigned int expected[RECORD__MAX] = {1, 1, 0};
#endif
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_REDIRECT */
	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	/* Test redirect calls */
	test_log(TEST_DRIVER_NAME ": mark 0x%lx", ctx->mark);
	test_log(TEST_DRIVER_NAME ": num_calls %u/%u/%u (tailcall/redirect/redirect_peer)",
		 num_calls[RECORD_TAILCALL],
		 num_calls[RECORD_REDIRECT],
		 num_calls[RECORD_REDIRECT_PEER]);

	if (ctx->mark != TEST_SKB_MARK)
		test_fatal(TEST_DRIVER_NAME ": Incorrect skb mark: 0x%lx != 0x%lx",
			   ctx->mark, TEST_SKB_MARK);
	if (num_calls[RECORD_TAILCALL] != expected[RECORD_TAILCALL])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of tail calls");
	if (num_calls[RECORD_REDIRECT] != expected[RECORD_REDIRECT])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of bpf_redirect() calls")
	if (num_calls[RECORD_REDIRECT_PEER] != expected[RECORD_REDIRECT_PEER])
		test_fatal(TEST_DRIVER_NAME ": Incorrect nunmber of bpf_redirect_peer() calls")

	/* Check the packet. */
	BUF_DECL(REDIRECT_HOST_IPV4_POST, tc_redirect_host_ipv4_post);
	ASSERT_CTX_BUF_OFF("tc_redirect_host_ipv4_post",
			   "Ether", ctx, sizeof(__u32),
			   REDIRECT_HOST_IPV4_POST,
			   sizeof(BUF(REDIRECT_HOST_IPV4_POST)));

	test_finish();
}

#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6

/* Setup for this test:
 * +--------External--------+    +----------Pod 1---------+
 * | v6_ext_one:high-port   | -> | v6_pod_one:tcp_svc_one |
 * +------------------------+    +------------------------+
 */
PKTGEN("tc", "tc_redirect_host_ipv6")
int tc_redirect_host_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(REDIRECT_HOST_IPV6_PRE, tc_redirect_host_ipv6_pre);
	BUILDER_PUSH_BUF(builder, REDIRECT_HOST_IPV6_PRE);

	pktgen__finish(&builder);

	return 0;
}

/* Test that sending a packet from a pod to its own service gets source nat-ed
 * and that it is forwarded to the correct veth.
 */
SETUP("tc", "tc_redirect_host_ipv6")
int tc_redirect_host_ipv6_setup(struct __ctx_buff *ctx)
{
	const union v6addr pod_ip = { .addr = v6_pod_one_addr };
	const union v6addr ext_ip = { .addr = v6_ext_node_one_addr };

	/* Add an IPCache entry for pod 1 */
	ipcache_v6_add_entry(&pod_ip, 0, 112233, 0, 0);

	/* Add endpoint for local LXC */
	endpoint_v6_add_entry(&pod_ip, TEST_LXC_IFACE, TEST_LXC_ID_LOCAL, 0, 0,
			      (const __u8 *)ep_mac, (const __u8 *)node_mac);

	/* Add source identity to test mark */
	ipcache_v6_add_entry(&ext_ip, 0, TEST_SRC_IDENTITY, 0, 0);

	return host_send_packet(ctx);
}

CHECK("tc", "tc_redirect_host_ipv6")
int tc_redirect_host_ipv6_check(__maybe_unused const struct __ctx_buff *ctx)
{
#ifdef __CONFIG_ENABLE_NETKIT
	const unsigned int expected[RECORD__MAX] = {1, 1, 0};
#elif defined(USE_BPF_PROG_FOR_INGRESS_POLICY)
	const unsigned int expected[RECORD__MAX] = {0, 1, 0};
#else
	const unsigned int expected[RECORD__MAX] = {1, 1, 0};
#endif
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_REDIRECT */
	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	/* Test redirect calls */
	test_log(TEST_DRIVER_NAME ": mark 0x%lx", ctx->mark);
	test_log(TEST_DRIVER_NAME ": num_calls %u/%u/%u (tailcall/redirect/redirect_peer)",
		 num_calls[RECORD_TAILCALL],
		 num_calls[RECORD_REDIRECT],
		 num_calls[RECORD_REDIRECT_PEER]);

	if (ctx->mark != TEST_SKB_MARK)
		test_fatal(TEST_DRIVER_NAME ": Incorrect skb mark: 0x%lx != 0x%lx",
			   ctx->mark, TEST_SKB_MARK);
	if (num_calls[RECORD_TAILCALL] != expected[RECORD_TAILCALL])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of tail calls");
	if (num_calls[RECORD_REDIRECT] != expected[RECORD_REDIRECT])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of bpf_redirect() calls")
	if (num_calls[RECORD_REDIRECT_PEER] != expected[RECORD_REDIRECT_PEER])
		test_fatal(TEST_DRIVER_NAME ": Incorrect nunmber of bpf_redirect_peer() calls")

	/* Check the packet. */
	BUF_DECL(REDIRECT_HOST_IPV6_POST, tc_redirect_host_ipv6_post);
	ASSERT_CTX_BUF_OFF("tc_redirect_host_ipv6_post",
			   "Ether", ctx, sizeof(__u32),
			   REDIRECT_HOST_IPV6_POST,
			   sizeof(BUF(REDIRECT_HOST_IPV6_POST)));

	test_finish();
}

#endif /* ENABLE_IPV6 */
