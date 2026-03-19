// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

/* Enable debug output */
#define DEBUG

/* Set the LXC source address to be the address of pod one */
#define LXC_IPV4 (__be32)v6_pod_one

/* Enable CT debug output */
#undef QUIET_CT

#include "pktgen.h"
#include "scapy.h"

/* Enable code paths under test */
#define ENABLE_IPV6

#include "lib/bpf_host.h"

#define V6_ALEN 16

ASSIGN_CONFIG(__u64, l2_announcements_max_liveness, 3000000000ULL)
ASSIGN_CONFIG(bool, enable_l2_announcements, true)
ASSIGN_CONFIG(union macaddr, interface_mac, {.addr = mac_two_addr})

struct icmp6_opthdr {
	__u8 type;
	__u8 length;
	__u8 llsrc_mac[ETH_ALEN];
};

/* packet defined in ./scapy/tc_l2_announce6_pkt_defs.py */
const __u8 l2_announce6_ns[] = {
	SCAPY_BUF_BYTES(l2_announce6_ns)
};

/* packet defined in ./scapy/tc_l2_announce6_pkt_defs.py */
const __u8 l2_announce6_targeted_ns[] = {
	SCAPY_BUF_BYTES(l2_announce6_targeted_ns)
};

/* packet defined in ./scapy/tc_l2_announce6_pkt_defs.py */
const __u8 l2_announce6_na[] = {
	SCAPY_BUF_BYTES(l2_announce6_na)
};

/* Setup for this test:
 * +-------------------------+   +--------------------------------------+    +--------------------------+
 * |L2:mac_one, L3:v6_ext_node_one|---|  ND Request broadcast for v6_svc_one |--->|L2:mac_two, L3:v6_node_one|
 * +-------------------------+   +--------------------------------------+    +--------------------------+
 *             ^   +-------------------------------------------------------------------+    |
 *             \---| ND Reply, SHR:mac_two, SIP:v6_svc_one, DHR:mac_one, DIP:v6_ext_node_one|---/
 *                 +-------------------------------------------------------------------+
 */

static __always_inline int build_packet(struct __ctx_buff *ctx, bool targeted)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	if (targeted)
		scapy_push_data(&builder, l2_announce6_targeted_ns,
				sizeof(l2_announce6_targeted_ns));
	else
		scapy_push_data(&builder, l2_announce6_ns,
				sizeof(l2_announce6_ns));

	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "0_no_entry")
int l2_announcement_nd_no_entry_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, false);
}

SETUP("tc", "0_no_entry")
int l2_announcement_nd_no_entry_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK("tc", "0_no_entry")
int l2_announcement_nd_no_entry_check(const struct __ctx_buff *ctx)
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

	ASSERT_CTX_BUF_OFF("tc_l2announce6_ns_no_entry_untouched",
			   "Ether", ctx,
			   sizeof(__u32), l2_announce6_ns,
			   sizeof(l2_announce6_ns));

	test_finish();
}

PKTGEN("tc", "0_no_entry_targeted")
int l2_announcement_nd_no_entry_tar_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, true);
}

SETUP("tc", "0_no_entry_targeted")
int l2_announcement_nd_no_entry_tar_setup(struct __ctx_buff *ctx)
{
	return netdev_receive_packet(ctx);
}

CHECK("tc", "0_no_entry_targeted")
int l2_announcement_nd_no_entry_tar_check(const struct __ctx_buff *ctx)
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

	ASSERT_CTX_BUF_OFF("tc_l2announce6_ns_tar_no_entry_untouched",
			   "Ether", ctx,
			   sizeof(__u32), l2_announce6_targeted_ns,
			   sizeof(l2_announce6_targeted_ns));

	test_finish();
}

PKTGEN("tc", "1_ok")
int l2_announcement_nd_ok_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, false);
}

int __l2_announcement_nd_ok_setup(struct __ctx_buff *ctx)
{
	struct l2_responder_v6_key key;
	struct l2_responder_stats value = {0};

	key.ifindex = 0;
	key.pad = 0;
	memcpy(&key.ip6, (void *)v6_svc_one, V6_ALEN);
	map_update_elem(&cilium_l2_responder_v6, &key, &value, BPF_ANY);

	config_set(RUNTIME_CONFIG_AGENT_LIVENESS, ktime_get_ns());

	return netdev_receive_packet(ctx);
}

SETUP("tc", "1_ok")
int l2_announcement_nd_ok_setup(struct __ctx_buff *ctx)
{
	return __l2_announcement_nd_ok_setup(ctx);
}

CHECK("tc", "1_ok")
int l2_announcement_nd_ok_check(const struct __ctx_buff *ctx)
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

	ASSERT_CTX_BUF_OFF("tc_l2announce2_entry_found_na",
			   "Ether", ctx,
			   sizeof(__u32), l2_announce6_na,
			   sizeof(l2_announce6_na));

	test_finish();
}

PKTGEN("tc", "1_ok_targeted")
int l2_announcement_nd_ok_tar_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, true);
}

SETUP("tc", "1_ok_targeted")
int l2_announcement_nd_ok_tar_setup(struct __ctx_buff *ctx)
{
	return __l2_announcement_nd_ok_setup(ctx);
}

CHECK("tc", "1_ok_targeted")
int l2_announcement_nd_ok_tar_check(const struct __ctx_buff *ctx)
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

	ASSERT_CTX_BUF_OFF("tc_l2announce2_tar_entry_found_na",
			   "Ether", ctx,
			   sizeof(__u32), l2_announce6_na,
			   sizeof(l2_announce6_na));

	test_finish();
}
