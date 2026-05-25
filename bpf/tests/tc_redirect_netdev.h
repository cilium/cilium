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

/* Define netdev and LXC interface index. The netdev ifindex (TEST_HOST_IFACE
 * here) is also what the ctx_get_ingress_ifindex mock returns - this is how we
 * simulate the kernel-populated skb->ingress_ifindex that
 * BPF_PROG_TEST_RUN does not set up on its own.
 */
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

/* Override ctx_get_ingress_ifindex so should_redirect_peer() sees a value
 * that mirrors the real datapath instead of BPF_PROG_TEST_RUN's default
 * (which leaves __sk_buff->ingress_ifindex at 0 for synthetic skbs).
 * Each scenario sets this before dispatching:
 *   TEST_HOST_IFACE - simulates TC ingress on the physical netdev
 *                     (phys -> local Pod path).
 *   0               - simulates TC egress after netkit's ns crossing,
 *                     which the kernel scrubs (Pod -> local Pod path on
 *                     netkit).
 */
static volatile __u32 mock_ingress_ifindex = TEST_HOST_IFACE;

#define ctx_get_ingress_ifindex mock_ctx_get_ingress_ifindex
static __always_inline __maybe_unused __u32
mock_ctx_get_ingress_ifindex(const struct __sk_buff *ctx __maybe_unused)
{
	return mock_ingress_ifindex;
}

/* Load the appropriate BPF programs. */
#include "lib/bpf_host.h"

/* Mocked out policy function so we can test redirect_ep(). This stands in for
 * bpf_lxc's tail_ipv{4,6}_policy program: it reads the calling convention
 * meta that local_delivery_fill_meta() set and calls redirect_ep() with the
 * value of should_redirect_peer() as the real program would. Unlike the
 * cil_from_host test we don't gate on from_host=true: this path runs with
 * from_host=false (we entered via cil_from_netdev).
 */
int mock_tail_policy(struct __ctx_buff *ctx)
{
	__u32 delivery_flags = ctx_load_meta(ctx, CB_DELIVERY_FLAGS);
	bool do_redirect = delivery_flags & CB_DELIVERY_FLAGS_REDIRECT;
	bool use_redirect_peer = delivery_flags & CB_DELIVERY_FLAGS_USE_REDIRECT_PEER;

	if (do_redirect)
		return redirect_ep(ctx, CONFIG(interface_ifindex),
				   use_redirect_peer, false);

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

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"

#ifdef ENABLE_IPV4

/* packet defined in ./scapy/tc_redirect_pkt_defs.py (reused from the host
 * test - same external -> local Pod shape).
 */
const __u8 tc_redirect_netdev_ipv4_pre[] = {
	SCAPY_BUF_BYTES(tc_redirect_host_ipv4_pre)
};

const __u8 tc_redirect_netdev_ipv4_post[] = {
	SCAPY_BUF_BYTES(tc_redirect_host_ipv4_post)
};

/* Setup for this test:
 * +--------External--------+    +----------Pod 1---------+
 * | v4_ext_one:high-port   | -> | v4_pod_one:tcp_svc_one |
 * +------------------------+    +------------------------+
 *
 * Packet enters via cil_from_netdev (TC ingress on the physical netdev),
 * not via cil_from_host. With from_host=false and ingress_ifindex > 0 the
 * datapath must reach the target Pod via ctx_redirect_peer() on both veth
 * and netkit - that's the behavior the runtime arm of should_redirect_peer
 * encodes (and what 210b5866e0 inadvertently broke for netkit).
 */
PKTGEN("tc", "tc_redirect_netdev_ipv4")
int tc_redirect_netdev_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, tc_redirect_netdev_ipv4_pre,
			sizeof(tc_redirect_netdev_ipv4_pre));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_redirect_netdev_ipv4")
int tc_redirect_netdev_ipv4_setup(struct __ctx_buff *ctx)
{
	/* Reset counters in case a previous scenario ran in the same .o */
	num_calls[RECORD_TAILCALL] = 0;
	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;

	/* phys-netdev TC ingress: kernel sets ingress_ifindex */
	mock_ingress_ifindex = TEST_HOST_IFACE;

	/* Add an IPCache entry for pod 1 */
	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);

	/* Add endpoint for local LXC */
	endpoint_v4_add_entry(v4_pod_one, TEST_LXC_IFACE, TEST_LXC_ID_LOCAL, 0, 0, 0,
			      (const __u8 *)ep_mac, (const __u8 *)node_mac);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_redirect_netdev_ipv4")
int tc_redirect_netdev_ipv4_check(__maybe_unused const struct __ctx_buff *ctx)
{
	/* Both veth and netkit must take the redirect_peer() path here:
	 * ingress_ifindex > 0 makes the runtime arm true on netkit, and
	 * !enable_netkit makes the loadtime arm true on veth.
	 */
	const unsigned int expected[RECORD__MAX] = {1, 0, 1};
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(v4_pod_one);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	test_log(TEST_DRIVER_NAME ": num_calls %u/%u/%u (tailcall/redirect/redirect_peer)",
		 num_calls[RECORD_TAILCALL],
		 num_calls[RECORD_REDIRECT],
		 num_calls[RECORD_REDIRECT_PEER]);

	if (num_calls[RECORD_TAILCALL] != expected[RECORD_TAILCALL])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of tail calls");
	if (num_calls[RECORD_REDIRECT] != expected[RECORD_REDIRECT])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of bpf_redirect() calls")
	if (num_calls[RECORD_REDIRECT_PEER] != expected[RECORD_REDIRECT_PEER])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of bpf_redirect_peer() calls")

	test_finish();
}

/* Pod -> local Pod simulation:
 *
 * In production this enters via bpf_lxc's cil_from_container (a different
 * compilation unit we can't link in here), but the discriminator the fix
 * cares about is the value of ctx_get_ingress_ifindex() in
 * should_redirect_peer(). Reuse cil_from_netdev as the vehicle and force
 * the mock to return 0, which is what netkit's ns crossing scrubs the
 * field to on TC egress. On netkit this must NOT take redirect_peer(); on
 * veth the loadtime !enable_netkit arm still folds true so redirect_peer()
 * is the right answer (and matches the existing tc_redirect_lxc_veth_*
 * expectations).
 */
PKTGEN("tc", "tc_redirect_pod_egress_ipv4")
int tc_redirect_pod_egress_ipv4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, tc_redirect_netdev_ipv4_pre,
			sizeof(tc_redirect_netdev_ipv4_pre));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_redirect_pod_egress_ipv4")
int tc_redirect_pod_egress_ipv4_setup(struct __ctx_buff *ctx)
{
	num_calls[RECORD_TAILCALL] = 0;
	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;

	/* Pod-egress on netkit: ns crossing scrubs ingress_ifindex to 0 */
	mock_ingress_ifindex = 0;

	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);
	endpoint_v4_add_entry(v4_pod_one, TEST_LXC_IFACE, TEST_LXC_ID_LOCAL, 0, 0, 0,
			      (const __u8 *)ep_mac, (const __u8 *)node_mac);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_redirect_pod_egress_ipv4")
int tc_redirect_pod_egress_ipv4_check(__maybe_unused const struct __ctx_buff *ctx)
{
#ifdef __CONFIG_ENABLE_NETKIT
	/* netkit + ingress_ifindex==0: predicate is false on both arms,
	 * so should_redirect_peer() returns false and the tail-called
	 * mock_tail_policy uses ctx_redirect() (which on netkit lets the
	 * primary's xmit handle the ns switch).
	 */
	const unsigned int expected[RECORD__MAX] = {1, 1, 0};
#else
	/* veth + ingress_ifindex==0: !CONFIG(enable_netkit) folds true at
	 * load time so should_redirect_peer() still returns true. veth Pod
	 * -> Pod uses redirect_peer() and matches tc_redirect_lxc_veth_*.
	 */
	const unsigned int expected[RECORD__MAX] = {1, 0, 1};
#endif
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(v4_pod_one);

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	test_log(TEST_DRIVER_NAME ": pod num %u/%u/%u (tc/r/rp)",
		 num_calls[RECORD_TAILCALL],
		 num_calls[RECORD_REDIRECT],
		 num_calls[RECORD_REDIRECT_PEER]);

	if (num_calls[RECORD_TAILCALL] != expected[RECORD_TAILCALL])
		test_fatal(TEST_DRIVER_NAME ": pod bad tail count");
	if (num_calls[RECORD_REDIRECT] != expected[RECORD_REDIRECT])
		test_fatal(TEST_DRIVER_NAME ": pod bad redirect count")
	if (num_calls[RECORD_REDIRECT_PEER] != expected[RECORD_REDIRECT_PEER])
		test_fatal(TEST_DRIVER_NAME ": pod bad redirect_peer count")

	test_finish();
}

#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6

const __u8 tc_redirect_netdev_ipv6_pre[] = {
	SCAPY_BUF_BYTES(tc_redirect_host_ipv6_pre)
};

const __u8 tc_redirect_netdev_ipv6_post[] = {
	SCAPY_BUF_BYTES(tc_redirect_host_ipv6_post)
};

PKTGEN("tc", "tc_redirect_netdev_ipv6")
int tc_redirect_netdev_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, tc_redirect_netdev_ipv6_pre,
			sizeof(tc_redirect_netdev_ipv6_pre));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_redirect_netdev_ipv6")
int tc_redirect_netdev_ipv6_setup(struct __ctx_buff *ctx)
{
	const union v6addr pod_ip = { .addr = v6_pod_one_addr };

	num_calls[RECORD_TAILCALL] = 0;
	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	mock_ingress_ifindex = TEST_HOST_IFACE;

	ipcache_v6_add_entry(&pod_ip, 0, 112233, 0, 0);

	endpoint_v6_add_entry(&pod_ip, TEST_LXC_IFACE, TEST_LXC_ID_LOCAL, 0, 0,
			      (const __u8 *)ep_mac, (const __u8 *)node_mac);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_redirect_netdev_ipv6")
int tc_redirect_netdev_ipv6_check(__maybe_unused const struct __ctx_buff *ctx)
{
	const unsigned int expected[RECORD__MAX] = {1, 0, 1};
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

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	test_log(TEST_DRIVER_NAME ": num_calls %u/%u/%u (tailcall/redirect/redirect_peer)",
		 num_calls[RECORD_TAILCALL],
		 num_calls[RECORD_REDIRECT],
		 num_calls[RECORD_REDIRECT_PEER]);

	if (num_calls[RECORD_TAILCALL] != expected[RECORD_TAILCALL])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of tail calls");
	if (num_calls[RECORD_REDIRECT] != expected[RECORD_REDIRECT])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of bpf_redirect() calls")
	if (num_calls[RECORD_REDIRECT_PEER] != expected[RECORD_REDIRECT_PEER])
		test_fatal(TEST_DRIVER_NAME ": Incorrect number of bpf_redirect_peer() calls")

	test_finish();
}

/* See the IPv4 sibling for the rationale of this scenario. */
PKTGEN("tc", "tc_redirect_pod_egress_ipv6")
int tc_redirect_pod_egress_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	scapy_push_data(&builder, tc_redirect_netdev_ipv6_pre,
			sizeof(tc_redirect_netdev_ipv6_pre));

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_redirect_pod_egress_ipv6")
int tc_redirect_pod_egress_ipv6_setup(struct __ctx_buff *ctx)
{
	const union v6addr pod_ip = { .addr = v6_pod_one_addr };

	num_calls[RECORD_TAILCALL] = 0;
	num_calls[RECORD_REDIRECT] = 0;
	num_calls[RECORD_REDIRECT_PEER] = 0;
	mock_ingress_ifindex = 0;

	ipcache_v6_add_entry(&pod_ip, 0, 112233, 0, 0);
	endpoint_v6_add_entry(&pod_ip, TEST_LXC_IFACE, TEST_LXC_ID_LOCAL, 0, 0,
			      (const __u8 *)ep_mac, (const __u8 *)node_mac);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "tc_redirect_pod_egress_ipv6")
int tc_redirect_pod_egress_ipv6_check(__maybe_unused const struct __ctx_buff *ctx)
{
#ifdef __CONFIG_ENABLE_NETKIT
	const unsigned int expected[RECORD__MAX] = {1, 1, 0};
#else
	const unsigned int expected[RECORD__MAX] = {1, 0, 1};
#endif
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

	status_code = data;
	assert(*status_code == CTX_ACT_REDIRECT);

	test_log(TEST_DRIVER_NAME ": pod num %u/%u/%u (tc/r/rp)",
		 num_calls[RECORD_TAILCALL],
		 num_calls[RECORD_REDIRECT],
		 num_calls[RECORD_REDIRECT_PEER]);

	if (num_calls[RECORD_TAILCALL] != expected[RECORD_TAILCALL])
		test_fatal(TEST_DRIVER_NAME ": pod bad tail count");
	if (num_calls[RECORD_REDIRECT] != expected[RECORD_REDIRECT])
		test_fatal(TEST_DRIVER_NAME ": pod bad redirect count")
	if (num_calls[RECORD_REDIRECT_PEER] != expected[RECORD_REDIRECT_PEER])
		test_fatal(TEST_DRIVER_NAME ": pod bad redirect_peer count")

	test_finish();
}

#endif /* ENABLE_IPV6 */
