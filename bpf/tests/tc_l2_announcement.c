// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

/* Enable debug output */
#define DEBUG

/* Enable CT debug output */
#undef QUIET_CT

#include "pktgen.h"
#include "scapy.h"

/* Enable code paths under test */
#define ENABLE_IPV4

#include "lib/bpf_host.h"

ASSIGN_CONFIG(__u64, l2_announcements_max_liveness, 3000000000ULL)
ASSIGN_CONFIG(bool, enable_l2_announcements, true)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr})

/* Setup for this test:
 * +-------------------------+   +--------------------------------------+    +--------------------------+
 * |L2:mac_one, L3:v4_ext_one|---| ARP Request broadcast for v4_svc_one |--->|L2:mac_two, L3:v4_node_one|
 * +-------------------------+   +--------------------------------------+    +--------------------------+
 *             ^   +-------------------------------------------------------------------+    |
 *             \---|ARP Reply, SHR:mac_two, SIP:v4_svc_one, DHR:mac_one, DIP:v4_ext_one|---/
 *                 +-------------------------------------------------------------------+
 */

static __always_inline int build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	BUF_DECL(ARP_REQ, l2_announce_arp_req);
	BUILDER_PUSH_BUF(builder, ARP_REQ);

	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "0_no_entry")
int l2_announcement_arp_no_entry_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

/* Test that sending a ARP broadcast request without entries in the map.
 */
SETUP("tc", "0_no_entry")
int l2_announcement_arp_no_entry_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK("tc", "0_no_entry")
int l2_announcement_arp_no_entry_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_OK);

	BUF_DECL(EXPECTED_ARP_REQ, l2_announce_arp_req);
	ASSERT_CTX_BUF_OFF("arp_req_no_entry_untouched", "Ether", ctx,
			   sizeof(__u32), EXPECTED_ARP_REQ,
			   sizeof(BUF(EXPECTED_ARP_REQ)));
	test_finish();

}

PKTGEN("tc", "1_happy_path")
int l2_announcement_arp_happy_path_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

/* Test that sending a ARP broadcast request matching an entry in
 * cilium_l2_responder_v4 results in a valid ARP reply.
 */
SETUP("tc", "1_happy_path")
int l2_announcement_arp_happy_path_setup(struct __ctx_buff *ctx)
{
	struct l2_responder_v4_key key;
	struct l2_responder_stats value = {0};

	key.ifindex = 0;
	key.ip4 = v4_svc_one;
	map_update_elem(&cilium_l2_responder_v4, &key, &value, BPF_ANY);

	config_set(RUNTIME_CONFIG_AGENT_LIVENESS, ktime_get_ns());

	return netdev_receive_packet(ctx);
}

CHECK("tc", "1_happy_path")
int l2_announcement_arp_happy_path_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT);

	BUF_DECL(EXPECTED_ARP_REP, l2_announce_arp_reply);

	ASSERT_CTX_BUF_OFF("arp_rep_ok", "Ether", ctx, sizeof(__u32),
			   EXPECTED_ARP_REP, sizeof(BUF(EXPECTED_ARP_REP)));
	test_finish();
}
