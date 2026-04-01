/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright Authors of Cilium
 */

#if !defined(ENABLE_WIREGUARD) && !defined(ENABLE_IPSEC)
# error "At least one of ENABLE_WIREGUARD or ENABLE_IPSEC must be defined
#endif

#define ENABLE_IPV4
#define ENABLE_IPV6

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#include "lib/bpf_host.h"

#include "lib/ipcache.h"
#include "lib/node.h"
#include "scapy.h"

ASSIGN_CONFIG(__u16, wg_port, 51871)

#ifdef ENABLE_WIREGUARD
/* packet defined in ./scapy/wg_from_netdev_pkt_defs.py */
const __u8 v4_wireguard[] = {
	SCAPY_BUF_BYTES(v4_wireguard)
};

/* packet defined in ./scapy/wg_from_netdev_pkt_defs.py */
const __u8 v6_wireguard[] = {
	SCAPY_BUF_BYTES(v6_wireguard)
};
#endif

#ifdef ENABLE_IPSEC
/* packet defined in ./scapy/ipsec_from_netdev_pkt_defs.py */
const __u8 v4_ipsec[] = {
	SCAPY_BUF_BYTES(v4_ipsec)
};

/* packet defined in ./scapy/ipsec_from_netdev_pkt_defs.py */
const __u8 v6_ipsec[] = {
	SCAPY_BUF_BYTES(v6_ipsec)
};
#endif

int pktgen(struct __ctx_buff *ctx, bool ipv4)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

#ifdef ENABLE_WIREGUARD
	if (ipv4)
		scapy_push_data(&builder, v4_wireguard, sizeof(v4_wireguard));
	else
		scapy_push_data(&builder, v6_wireguard, sizeof(v6_wireguard));
#endif
#ifdef ENABLE_IPSEC
	if (ipv4)
		scapy_push_data(&builder, v4_ipsec, sizeof(v4_ipsec));
	else
		scapy_push_data(&builder, v6_ipsec, sizeof(v6_ipsec));
#endif

	pktgen__finish(&builder);
	return 0;
}

/* The setup function adds the necessary state to properly pass up the packet to
 * the stack with the MARK_MAGIC_DECRYPT mark set.
 * - For WireGuard, this means adding an entry to the IPCache (resolve_srcid_ipv{4,6} in bpf_host)
 * - For IPSec, this means adding an entry to the node map (lookup_ip{4,6}_node_id in bpf_host)
 */
int setup(struct __ctx_buff *ctx, bool ipv4)
{
#ifdef ENABLE_IPSEC
	if (ipv4)
		node_v4_add_entry(v4_node_one, REMOTE_NODE_ID, 3);
	else
		node_v6_add_entry((union v6addr *)v6_node_one, REMOTE_NODE_ID, 3);
#endif

#ifdef ENABLE_WIREGUARD
	if (ipv4)
		ipcache_v4_add_entry(v4_node_one, 0, REMOTE_NODE_ID, 0, 255);
	else
		ipcache_v6_add_entry((union v6addr *)v6_node_one, 0, REMOTE_NODE_ID, 0, 255);
#endif

	return netdev_receive_packet(ctx);
}

int check(const struct __ctx_buff *ctx, bool ipv4)
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

	assert(*status_code == CTX_ACT_OK);

	assert(ctx_is_decrypt(ctx));

#ifdef ENABLE_WIREGUARD
	if (ipv4) {
		ASSERT_CTX_BUF_OFF("v4_wg_pkt_ok", "Ether", ctx, sizeof(__u32),
				   v4_wireguard, sizeof(v4_wireguard));
	} else {
		ASSERT_CTX_BUF_OFF("v6_wg_pkt_ok", "Ether", ctx, sizeof(__u32),
				   v6_wireguard, sizeof(v6_wireguard));
	}
#endif
#ifdef ENABLE_IPSEC
	if (ipv4) {
		ASSERT_CTX_BUF_OFF("v4_ipsec_pkt_ok", "Ether", ctx, sizeof(__u32),
				   v4_ipsec, sizeof(v4_ipsec));
	} else {
		ASSERT_CTX_BUF_OFF("v6_ipsec_pkt_ok", "Ether", ctx, sizeof(__u32),
				   v6_ipsec, sizeof(v6_ipsec));
	}
#endif

	test_finish();
}

/* These tests validate that a real encrypted packet is handled properly.
 * For both WireGuard and IPSec, we expect the packet to not be modified,
 * and to be passed up the stack with the MARK_MAGIC_DECRYPT mark set.
 */
PKTGEN("tc", "encrypted_v4")
int encrypted_v4_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, true);
}

SETUP("tc", "encrypted_v4")
int encrypted_v4_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, true);
}

CHECK("tc", "encrypted_v4")
int encrypted_v4_check(const struct __ctx_buff *ctx)
{
	return check(ctx, true);
}

PKTGEN("tc", "encrypted_v6")
int encrypted_v6_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, false);
}

SETUP("tc", "encrypted_v6")
int encrypted_v6_setup(struct __ctx_buff *ctx)
{
	return setup(ctx, false);
}

CHECK("tc", "encrypted_v6")
int encrypted_v6_check(const struct __ctx_buff *ctx)
{
	return check(ctx, false);
}
