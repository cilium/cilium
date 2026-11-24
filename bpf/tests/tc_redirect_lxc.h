/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "scapy.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1

/* Enable CT debug output */
#undef QUIET_CT

/* Define an endpoint ID that we'll use as index into policy maps. */
#define TEST_LXC_ID_LOCAL_V4 234
#define TEST_LXC_ID_LOCAL_V6 235

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

static __always_inline
void clear_records(void)
{
	/* Reset counters in case a previous scenario ran in the same .o */
	num_calls[RECORD_TAILCALL] = 0;
	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
}

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

static inline int tail_ipv4_ct_ingress_policy_only(struct __ctx_buff *ctx);

__section_entry
int mock_handle_policy4(struct __ctx_buff *ctx)
{
	num_calls[RECORD_TAILCALL]++;

	/* If we've invoked a policy tailcall exactly once, we can proceed to
	 * a redirect. In the case of bpf_lxc, we need to call the subsequent
	 * policy function manually to get to the final redirect_ep() call.
	 */
	if (num_calls[RECORD_TAILCALL] == 1)
		return tail_ipv4_ct_ingress_policy_only(ctx);

	return CTX_ACT_DROP;
}

static inline int tail_ipv6_ct_ingress_policy_only(struct __ctx_buff *ctx);

__section_entry
int mock_handle_policy6(struct __ctx_buff *ctx)
{
	num_calls[RECORD_TAILCALL]++;

	/* If we've invoked a policy tailcall exactly once, we can proceed to
	 * a redirect. In the case of bpf_lxc, we need to call the subsequent
	 * policy function manually to get to the final redirect_ep() call.
	 */
	if (num_calls[RECORD_TAILCALL] == 1)
		return tail_ipv6_ct_ingress_policy_only(ctx);

	return CTX_ACT_DROP;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[TEST_LXC_ID_LOCAL_V4] = &mock_handle_policy4,
		[TEST_LXC_ID_LOCAL_V6] = &mock_handle_policy6,
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
ASSIGN_CONFIG(bool, enable_ipv4, true)
ASSIGN_CONFIG(bool, enable_ipv6, true)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })

/* Deal with all configuration permutations that affect the operation of
 * the local_delivery code paths:
 *
 * - Datapath driver
 * - BPF host routing
 * - Per-endpoint routes
 */
#ifdef __CONFIG_ENABLE_NETKIT
#define TEST_DRIVER_NAME "netkit"
ASSIGN_CONFIG(bool, enable_netkit, true)
#else
#define TEST_DRIVER_NAME "veth"
ASSIGN_CONFIG(bool, enable_netkit, false)
#endif
#ifdef __CONFIG_ENABLE_BPF_HOST_ROUTING
#define TEST_ROUTING_NAME "+bpf"
ASSIGN_CONFIG(bool, enable_bpf_host_routing, true)
#else
#define TEST_ROUTING_NAME "+legacy"
ASSIGN_CONFIG(bool, enable_bpf_host_routing, false)
#endif
#ifdef __CONFIG_ENABLE_ENDPOINT_ROUTES
#define TEST_EPROUTES_NAME "+epr"
ASSIGN_CONFIG(bool, enable_endpoint_routes, true)
#else
#define TEST_EPROUTES_NAME ""
ASSIGN_CONFIG(bool, enable_endpoint_routes, false)
#endif

#define TEST_CONFIG_NAME TEST_DRIVER_NAME TEST_ROUTING_NAME TEST_EPROUTES_NAME

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"

/* Test 1 ---------------------------------------------------------------------------------
 *
 * Under netkit, with BPF host routing:
 *  - Per-endpoint route configuration is ignored, because in this test
 *    scenario ingress_ifindex==0 is assumed. (We are focused on bpf_lxc, see
 *    tc_redirect_netdev for physical -> netkit pod.)
 *  - We should then expect a bpf_redirect() because netkit cannot currently
 *    do a bpf_redirect_peer() (netns switched to destination pod before BPF
 *    called).
 *
 * Note, netkit does not run under legacy host routing, so that configuration is
 * not provided for here.
 *
 * Under veth, with BPF host routing:
 *  - Per-endpoint route configuration is ignored by local_delivery code.
 *  - Instead, we expect to tail call into policy code, and then do a
 *    bpf_redirect_peer() to bypass cil_to_container.
 *
 * Under veth, with legacy host routing:
 *  - Per-endpoint route configuration is important to local_delivery code.
 *  - We expect a standard bpf_redirect() to trigger cil_to_container.
 *  - No tailcall.
 */
#ifdef __CONFIG_ENABLE_NETKIT
#define TEST1_EXPECTED_NUM_CALLS { 1, 1, 0 }
#else /* !netkit */
#ifdef __CONFIG_ENABLE_BPF_HOST_ROUTING
#define TEST1_EXPECTED_NUM_CALLS { 1, 0, 1 }
#elif defined(__CONFIG_ENABLE_ENDPOINT_ROUTES)
#define TEST1_EXPECTED_NUM_CALLS { 0, 1, 0 }
#else
#define TEST1_EXPECTED_NUM_CALLS { 1, 1, 0 }
#endif
#endif

/* packet defined in ./scapy/tc_redirect_pkt_defs.py */
const __u8 tc_redirect_lxc_ipv4_pre[] = {
	SCAPY_BUF_BYTES(tc_redirect_lxc_ipv4_pre)
};

/* packet defined in ./scapy/tc_redirect_pkt_defs.py */
const __u8 tc_redirect_lxc_ipv4_post[] = {
	SCAPY_BUF_BYTES(tc_redirect_lxc_ipv4_post)
};

/* Setup for this test:
 * +-------ClusterIP--------+    +----------Pod 1---------+
 * | v4_svc_one:tcp_svc_one | -> | v4_pod_one:tcp_svc_one |
 * +------------------------+    +------------------------+
 *            ^                            |
 *            \---------------------------/
 */
PKTGEN(PROG_TYPE, "tc_redirect_lxc_ipv4")
int tc_redirect_lxc_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, tc_redirect_lxc_ipv4_pre,
			sizeof(tc_redirect_lxc_ipv4_pre));

	pktgen__finish(&builder);

	return 0;
}

/* Test that sending a packet from a pod to its own service gets source nat-ed
 * and that it is forwarded via the correct BPF redirect helper.
 */
SETUP(PROG_TYPE, "tc_redirect_lxc_ipv4")
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
	endpoint_v4_add_entry(v4_pod_one, 0, TEST_LXC_ID_LOCAL_V4, 0, 0, 0,
			      (const __u8 *)ep_mac, (const __u8 *)node_mac);

	clear_records();
	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "tc_redirect_lxc_ipv4")
int tc_redirect_lxc_ipv4_check(__maybe_unused const struct __ctx_buff *ctx)
{
	const unsigned int expected[RECORD__MAX] = TEST1_EXPECTED_NUM_CALLS;
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(v4_pod_one);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_REDIRECT */
	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	/* Test redirect usage */
	test_log(TEST_CONFIG_NAME ": test1 %u/%u/%u (tc/r/rp)",
		 num_calls[RECORD_TAILCALL],
		 num_calls[RECORD_REDIRECT],
		 num_calls[RECORD_REDIRECT_PEER]);
	if (num_calls[RECORD_TAILCALL] != expected[RECORD_TAILCALL])
		test_fatal(TEST_CONFIG_NAME ": Incorrect number of tail calls");
	if (num_calls[RECORD_REDIRECT] != expected[RECORD_REDIRECT])
		test_fatal(TEST_CONFIG_NAME ": Incorrect number of bpf_redirect() calls")
	if (num_calls[RECORD_REDIRECT_PEER] != expected[RECORD_REDIRECT_PEER])
		test_fatal(TEST_CONFIG_NAME ": Incorrect nunmber of bpf_redirect_peer() calls")

	/* Check the packet. */
	ASSERT_CTX_BUF_OFF("tc_redirect_lxc_ipv4_post",
			   "Ether", ctx, sizeof(__u32),
			   tc_redirect_lxc_ipv4_post,
			   sizeof(tc_redirect_lxc_ipv4_post));

	test_finish();
}

/* packet defined in ./scapy/tc_redirect_pkt_defs.py */
const __u8 tc_redirect_lxc_ipv6_pre[] = {
	SCAPY_BUF_BYTES(tc_redirect_lxc_ipv6_pre)
};

/* packet defined in ./scapy/tc_redirect_pkt_defs.py */
const __u8 tc_redirect_lxc_ipv6_post[] = {
	SCAPY_BUF_BYTES(tc_redirect_lxc_ipv6_post)
};

/* Setup for this test:
 * +-------ClusterIP--------+    +----------Pod 1---------+
 * | v6_svc_one:tcp_svc_one | -> | v6_pod_one:tcp_svc_one |
 * +------------------------+    +------------------------+
 *            ^                            |
 *            \---------------------------/
 */
PKTGEN(PROG_TYPE, "tc_redirect_lxc_ipv6")
int tc_redirect_lxc_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, tc_redirect_lxc_ipv6_pre,
			sizeof(tc_redirect_lxc_ipv6_pre));

	pktgen__finish(&builder);

	return 0;
}

/* Test that sending a packet from a pod to its own service gets source nat-ed
 * and that it is forwarded via the correct BPF redirect helper.
 */
SETUP(PROG_TYPE, "tc_redirect_lxc_ipv6")
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
	endpoint_v6_add_entry(&pod_ip, 0, TEST_LXC_ID_LOCAL_V6, 0, 0,
			      (const __u8 *)ep_mac, (const __u8 *)node_mac);

	clear_records();
	return pod_send_packet(ctx);
}

CHECK(PROG_TYPE, "tc_redirect_lxc_ipv6")
int tc_redirect_lxc_ipv6_check(__maybe_unused const struct __ctx_buff *ctx)
{
	const unsigned int expected[RECORD__MAX] = TEST1_EXPECTED_NUM_CALLS;
	const union v6addr pod_ip = { .addr = v6_pod_one_addr };
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v6_del_entry(&pod_ip);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Should trigger CTX_ACT_REDIRECT */
	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	/* Test redirect usage */
	test_log(TEST_CONFIG_NAME ": test1 %u/%u/%u (tc/r/rp)",
		 num_calls[RECORD_TAILCALL],
		 num_calls[RECORD_REDIRECT],
		 num_calls[RECORD_REDIRECT_PEER]);
	if (num_calls[RECORD_TAILCALL] != expected[RECORD_TAILCALL])
		test_fatal(TEST_CONFIG_NAME ": Incorrect number of tail calls");
	if (num_calls[RECORD_REDIRECT] != expected[RECORD_REDIRECT])
		test_fatal(TEST_CONFIG_NAME ": Incorrect number of bpf_redirect() calls")
	if (num_calls[RECORD_REDIRECT_PEER] != expected[RECORD_REDIRECT_PEER])
		test_fatal(TEST_CONFIG_NAME ": Incorrect nunmber of bpf_redirect_peer() calls")

	/* Check the packet. */
	ASSERT_CTX_BUF_OFF("tc_redirect_lxc_ipv6_post",
			   "Ether", ctx, sizeof(__u32),
			   tc_redirect_lxc_ipv6_post,
			   sizeof(tc_redirect_lxc_ipv6_post));

	test_finish();
}
