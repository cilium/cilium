// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define WG_SPI 255
#define POD1_ID 10000
#define POD2_ID 10001
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_WIREGUARD 1
#define ENABLE_NODE_ENCRYPTION

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#include "lib/bpf_host.h"

#include "lib/ipcache.h"
#include "scapy.h"

ASSIGN_CONFIG(__u16, wg_port, 51871)

/* This test validates that a plain-text pod-to-pod IPv4 packet going through the
 * cil_to_netdev hook is being redirected for WireGuard encryption.
 */
PKTGEN("tc", "ipv4_plain_pod_to_pod_wireguard_to_netdev")
int ipv4_plain_pod_to_pod_wireguard_to_netdev_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V4_POD_TO_POD_TO_WIREGUARD, v4_overlay_tcp_packet);
	BUILDER_PUSH_BUF(builder, V4_POD_TO_POD_TO_WIREGUARD);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv4_plain_pod_to_pod_wireguard_to_netdev")
int ipv4_plain_pod_to_pod_wireguard_to_netdev_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry_with_flags(v4_pod_one, 0, POD1_ID, v4_node_one, WG_SPI, false);
	ipcache_v4_add_entry_with_flags(v4_pod_two, 0, POD2_ID, v4_node_two, WG_SPI, false);

	return netdev_send_packet(ctx);
}

CHECK("tc", "ipv4_plain_pod_to_pod_wireguard_to_netdev")
int ipv4_plain_pod_to_pod_wireguard_to_netdev_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	status_code = data;

	assert(data + sizeof(*status_code) <= data_end);

	assert(*status_code == CTX_ACT_REDIRECT);

	BUF_DECL(V4_POD_TO_POD_TO_WIREGUARD, v4_overlay_tcp_packet);
	ASSERT_CTX_BUF_OFF("v4_wg_pkt_ok", "Ether", ctx, sizeof(__u32),
			   V4_POD_TO_POD_TO_WIREGUARD, sizeof(BUF(V4_POD_TO_POD_TO_WIREGUARD)));

	test_finish();
}

/* This test validates that a plain-text pod-to-pod IPv6 packet going through the
 * cil_to_netdev hook is being redirected for WireGuard encryption.
 */
PKTGEN("tc", "ipv6_plain_pod_to_pod_wireguard_to_netdev")
int ipv6_plain_pod_to_pod_wireguard_to_netdev_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	BUF_DECL(V6_POD_TO_POD_TO_WIREGUARD, v6_overlay_tcp_packet);
	BUILDER_PUSH_BUF(builder, V6_POD_TO_POD_TO_WIREGUARD);

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ipv6_plain_pod_to_pod_wireguard_to_netdev")
int ipv6_plain_pod_to_pod_wireguard_to_netdev_setup(struct __ctx_buff *ctx)
{
	ipcache_v6_add_entry_with_flags((union v6addr *)v6_pod_one, 0, POD1_ID, v4_node_one, WG_SPI, false);
	ipcache_v6_add_entry_with_flags((union v6addr *)v6_pod_two, 0, POD2_ID, v4_node_two, WG_SPI, false);

	return netdev_send_packet(ctx);
}

CHECK("tc", "ipv6_plain_pod_to_pod_wireguard_to_netdev")
int ipv6_plain_pod_to_pod_wireguard_to_netdev_check(const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	status_code = data;

	assert(data + sizeof(*status_code) <= data_end);

	assert(*status_code == CTX_ACT_REDIRECT);

	BUF_DECL(V6_POD_TO_POD_TO_WIREGUARD, v6_overlay_tcp_packet);
	ASSERT_CTX_BUF_OFF("v6_wg_pkt_ok", "Ether", ctx, sizeof(__u32),
			   V6_POD_TO_POD_TO_WIREGUARD, sizeof(BUF(V6_POD_TO_POD_TO_WIREGUARD)));

	test_finish();
}
