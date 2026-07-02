// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Test strict ingress encryption enforcement on the native routing path.
 * When strict ingress mode is enabled, cleartext pod-to-pod traffic that
 * arrives from a netdev and resolves to a local pod endpoint must be dropped.
 */

#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_WIREGUARD	1

#define DEST_LXC_ID	0

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

__section_entry
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_OK;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[DEST_LXC_ID] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

#include "lib/bpf_host.h"
#include "lib/ipcache.h"
#include "lib/endpoint.h"

ASSIGN_CONFIG(bool, encryption_strict_ingress, true)

#define SRC_POD_SEC_IDENTITY	(CIDR_IDENTITY_RANGE_START - 2)

static __always_inline int
build_packet(struct __ctx_buff *ctx, bool ipv4)
{
	struct pktgen builder;
	void *l4;

	pktgen__init(&builder, ctx);

	if (ipv4)
		l4 = pktgen__push_ipv4_tcp_packet(&builder,
						  (__u8 *)mac_one, (__u8 *)mac_two,
						  v4_pod_one, v4_pod_two,
						  bpf_htons(12345), bpf_htons(80));
	else
		l4 = pktgen__push_ipv6_tcp_packet(&builder,
						  (__u8 *)mac_one, (__u8 *)mac_two,
						  (__u8 *)v6_pod_one,
						  (__u8 *)v6_pod_two,
						  bpf_htons(12345), bpf_htons(80));
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
setup(struct __ctx_buff *ctx, bool ipv4)
{
	/* Map the source IP to a cluster-internal pod identity so that the
	 * strict-ingress predicate matches.
	 */
	if (ipv4)
		ipcache_v4_add_entry(v4_pod_one, 0, SRC_POD_SEC_IDENTITY, 0, 0);
	else
		ipcache_v6_add_entry((union v6addr *)v6_pod_one, 0,
				     SRC_POD_SEC_IDENTITY, 0, 0);

	/* Register the destination as a local pod endpoint. The strict-ingress
	 * check only runs once the packet resolves to a local endpoint, so
	 * without this the packet would skip the check entirely.
	 */
	if (ipv4)
		endpoint_v4_add_entry(v4_pod_two, 0, DEST_LXC_ID, 0, 0, 0,
				      (__u8 *)mac_two, (__u8 *)mac_one);
	else
		endpoint_v6_add_entry((union v6addr *)v6_pod_two, 0, DEST_LXC_ID,
				      0, 0, (__u8 *)mac_two, (__u8 *)mac_one);

	return netdev_receive_packet(ctx);
}

static __always_inline int
check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Cleartext pod-to-pod traffic must be dropped under strict mode. */
	assert(*status_code == CTX_ACT_DROP);

	test_finish();
}

PKTGEN("tc", "ipv4_strict_ingress_from_netdev")
int ipv4_strict_ingress_from_netdev_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, true);
}

SETUP("tc", "ipv4_strict_ingress_from_netdev")
int ipv4_strict_ingress_from_netdev_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, true);
}

CHECK("tc", "ipv4_strict_ingress_from_netdev")
int ipv4_strict_ingress_from_netdev_check(const struct __ctx_buff *ctx)
{
	return check(ctx);
}

PKTGEN("tc", "ipv6_strict_ingress_from_netdev")
int ipv6_strict_ingress_from_netdev_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, false);
}

SETUP("tc", "ipv6_strict_ingress_from_netdev")
int ipv6_strict_ingress_from_netdev_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, false);
}

CHECK("tc", "ipv6_strict_ingress_from_netdev")
int ipv6_strict_ingress_from_netdev_check(const struct __ctx_buff *ctx)
{
	return check(ctx);
}
