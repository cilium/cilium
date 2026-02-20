/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

/* Enable CT debug output */
#undef QUIET_CT

#include "pktgen.h"
#include "scapy.h"

/* We always assume we have BPF Host Routing enabled */
#define ENABLE_HOST_ROUTING 1

/* Forward declaration for tailcall routines because they're not provided
 * until we pull in bpf_lxc.
 *
 * Note: we only allow one address family to be enabled per test so the
 * test mock policy tailcall doesn't need to switch by address family.
 */
#if defined(ENABLE_IPV4) && !defined(ENABLE_IPV6)
static inline int tail_ipv4_ct_ingress_policy_only(struct __ctx_buff *ctx);
#define test_ct_ingress_policy_only tail_ipv4_ct_ingress_policy_only
#elif !defined(ENABLE_IPV4) && defined(ENABLE_IPV6)
static inline int tail_ipv6_ct_ingress_policy_only(struct __ctx_buff *ctx);
#define test_ct_ingress_policy_only tail_ipv6_ct_ingress_policy_only
#else
#error This test must set either ENABLE_IPV4 or ENABLE_IPV6, but not both.
#endif

/* Define an endpoint ID that we'll use as index into policy maps. */
#define TEST_LXC_ID_LOCAL 233

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

__section_entry
int mock_handle_policy(struct __ctx_buff *ctx)
{
	num_calls[RECORD_TAILCALL]++;

	/* If we've invoked a policy tailcall exactly once, we can proceed to
	 * a redirect. In the case of bpf_lxc, we need to call the subsequent
	 * policy function manually to get to the final redirect_ep() call.
	 */
	if (num_calls[RECORD_TAILCALL] == 1)
		return test_ct_ingress_policy_only(ctx);

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
#include "lib/bpf_lxc.h"

/* Assign necessary load-time configs */
#ifdef ENABLE_IPV4
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(union v4addr, service_loopback_ipv4, { .be32 = v4_svc_loopback })
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(union v6addr, service_loopback_ipv6, { .addr = v6_svc_loopback })
#endif /* ENABLE_IPV6 */

/* Deal with testing netkit or veth. */
#ifdef __CONFIG_ENABLE_NETKIT
#define TEST_DRIVER_NAME "netkit"
ASSIGN_CONFIG(bool, enable_netkit, true)
#else
#define TEST_DRIVER_NAME "veth"
ASSIGN_CONFIG(bool, enable_netkit, false)
#endif

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"

#ifdef ENABLE_IPV4

/* Setup for this test:
 * +-------ClusterIP--------+    +----------Pod 1---------+
 * | v4_svc_one:tcp_svc_one | -> | v4_pod_one:tcp_svc_one |
 * +------------------------+    +------------------------+
 *            ^                            |
 *            \---------------------------/
 */
PKTGEN("tc", "tc_redirect_lxc_ipv4")
int tc_redirect_lxc_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(REDIRECT_LXC_IPV4_PRE, tc_redirect_lxc_ipv4_pre);
	BUILDER_PUSH_BUF(builder, REDIRECT_LXC_IPV4_PRE);

	pktgen__finish(&builder);

	return 0;
}

/* Test that sending a packet from a pod to its own service gets source nat-ed
 * and that it is forwarded to the correct veth.
 */
SETUP("tc", "tc_redirect_lxc_ipv4")
int tc_redirect_lxc_ipv4_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Add ClusterIP */
	lb_v4_add_service(v4_svc_one, tcp_svc_one, IPPROTO_TCP, 1, revnat_id);
	lb_v4_add_backend(v4_svc_one, tcp_svc_one, 1, 124,
			  v4_pod_one, tcp_dst_one, IPPROTO_TCP, 0);

	/* Add an IPCache entry for pod 1 */
	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);

	/* Add endpoint for local LXC */
	endpoint_v4_add_entry(v4_pod_one, 0, TEST_LXC_ID_LOCAL, 0, 0, 0,
			      (const __u8 *)ep_mac, (const __u8 *)node_mac);

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_redirect_lxc_ipv4")
int tc_redirect_lxc_ipv4_check(__maybe_unused const struct __ctx_buff *ctx)
{
#ifdef __CONFIG_ENABLE_NETKIT
	const unsigned int expected[RECORD__MAX] = {1, 1, 0};
#else
	const unsigned int expected[RECORD__MAX] = {1, 0, 1};
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

	/* Test redirect usage */
	test_log(TEST_DRIVER_NAME ": num_calls %u/%u/%u (tailcall/redirect/redirect_peer)",
		 num_calls[RECORD_TAILCALL],
		 num_calls[RECORD_REDIRECT],
		 num_calls[RECORD_REDIRECT_PEER]);

	if (num_calls[RECORD_TAILCALL] != expected[RECORD_TAILCALL])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of tail calls");
	if (num_calls[RECORD_REDIRECT] != expected[RECORD_REDIRECT])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of bpf_redirect() calls")
	if (num_calls[RECORD_REDIRECT_PEER] != expected[RECORD_REDIRECT_PEER])
		test_fatal(TEST_DRIVER_NAME ": Incorrect nunmber of bpf_redirect_peer() calls")

	/* Check the packet. */
	BUF_DECL(REDIRECT_LXC_IPV4_POST, tc_redirect_lxc_ipv4_post);
	ASSERT_CTX_BUF_OFF("tc_redirect_lxc_ipv4_post",
			   "Ether", ctx, sizeof(__u32),
			   REDIRECT_LXC_IPV4_POST,
			   sizeof(BUF(REDIRECT_LXC_IPV4_POST)));

	test_finish();
}

#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6

/* Setup for this test:
 * +-------ClusterIP--------+    +----------Pod 1---------+
 * | v6_svc_one:tcp_svc_one | -> | v6_pod_one:tcp_svc_one |
 * +------------------------+    +------------------------+
 *            ^                            |
 *            \---------------------------/
 */
PKTGEN("tc", "tc_redirect_lxc_ipv6")
int tc_redirect_lxc_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(REDIRECT_LXC_IPV6_PRE, tc_redirect_lxc_ipv6_pre);
	BUILDER_PUSH_BUF(builder, REDIRECT_LXC_IPV6_PRE);

	pktgen__finish(&builder);

	return 0;
}

/* Test that sending a packet from a pod to its own service gets source nat-ed
 * and that it is forwarded to the correct veth.
 */
SETUP("tc", "tc_redirect_lxc_ipv6")
int tc_redirect_lxc_ipv6_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;
	const union v6addr service_ip = { .addr = v6_svc_one_addr };
	const union v6addr pod_ip = { .addr = v6_pod_one_addr };

	/* Add ClusterIP */
	lb_v6_add_service(&service_ip, tcp_svc_one, IPPROTO_TCP, 1, revnat_id);
	lb_v6_add_backend(&service_ip, tcp_svc_one, 1, 124,
			  &pod_ip, tcp_dst_one, IPPROTO_TCP, 0);

	/* Add an IPCache entry for pod 1 */
	ipcache_v6_add_entry(&pod_ip, 0, 112233, 0, 0);

	/* Add endpoint for local LXC */
	endpoint_v6_add_entry(&pod_ip, 0, TEST_LXC_ID_LOCAL, 0, 0,
			      (const __u8 *)ep_mac, (const __u8 *)node_mac);

	return pod_send_packet(ctx);
}

CHECK("tc", "tc_redirect_lxc_ipv6")
int tc_redirect_lxc_ipv6_check(__maybe_unused const struct __ctx_buff *ctx)
{
#ifdef __CONFIG_ENABLE_NETKIT
	const unsigned int expected[RECORD__MAX] = {1, 1, 0};
#else
	const unsigned int expected[RECORD__MAX] = {1, 0, 1};
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

	/* Test redirect usage */
	test_log(TEST_DRIVER_NAME ": num_calls %u/%u/%u (tailcall/redirect/redirect_peer)",
		 num_calls[RECORD_TAILCALL],
		 num_calls[RECORD_REDIRECT],
		 num_calls[RECORD_REDIRECT_PEER]);

	if (num_calls[RECORD_TAILCALL] != expected[RECORD_TAILCALL])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of tail calls");
	if (num_calls[RECORD_REDIRECT] != expected[RECORD_REDIRECT])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of bpf_redirect() calls")
	if (num_calls[RECORD_REDIRECT_PEER] != expected[RECORD_REDIRECT_PEER])
		test_fatal(TEST_DRIVER_NAME ": Incorrect nunmber of bpf_redirect_peer() calls")

	/* Check the packet. */
	BUF_DECL(REDIRECT_LXC_IPV6_POST, tc_redirect_lxc_ipv6_post);
	ASSERT_CTX_BUF_OFF("tc_redirect_lxc_ipv6_post",
			   "Ether", ctx, sizeof(__u32),
			   REDIRECT_LXC_IPV6_POST,
			   sizeof(BUF(REDIRECT_LXC_IPV6_POST)));

	test_finish();
}

#endif /* ENABLE_IPV6 */
