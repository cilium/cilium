/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright Authors of Cilium
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4			1
#define ENABLE_NODEPORT			1

#define SRC_POD_V4			v4_pod_one
#define SRC_POD_SEC_IDENTITY		(CIDR_IDENTITY_RANGE_START - 2)
#define NODE_IP				v4_node_one
#define SERVER_IP			v4_ext_one

#define SRC_PORT			bpf_htons(50000)
#define DST_PORT			bpf_htons(80)

#include "nodeport_defaults.h"

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/ipcache.h"

ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = NODE_IP })
ASSIGN_CONFIG(bool, enable_masquerade_ipv4, true)
ASSIGN_CONFIG(bool, enable_identity_mark, true)

static __always_inline
int v4_build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
					  SRC_POD_V4, SERVER_IP, SRC_PORT, DST_PORT);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline
int check(const struct __ctx_buff *ctx, __be32 expected_saddr)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) + sizeof(struct ethhdr) + sizeof(*l3) > data_end)
		test_fatal("packet out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l3 = data + sizeof(*status_code) + sizeof(struct ethhdr);
	assert(l3->saddr == expected_saddr);

	test_finish();
}

/* Validate that a pod packet leaving the cluster is masqueraded. */
PKTGEN(PROG_TYPE, "encrypt_masq_v4_1_unencrypted")
int encrypt_masq_v4_1_unencrypted_pktgen(struct __ctx_buff *ctx)
{
	return v4_build_packet(ctx);
}

SETUP(PROG_TYPE, "encrypt_masq_v4_1_unencrypted")
int encrypt_masq_v4_1_unencrypted_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(SRC_POD_V4, 0, 0, 0, SRC_POD_SEC_IDENTITY,
			      0, (__u8 *)mac_one, (__u8 *)mac_two);
	ipcache_v4_add_world_entry();

	set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_IDENTITY);

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "encrypt_masq_v4_1_unencrypted")
int encrypt_masq_v4_1_unencrypted_check(const struct __ctx_buff *ctx)
{
	return check(ctx, NODE_IP);
}

/* Validate that an already encrypted packet is not masqueraded. */
PKTGEN(PROG_TYPE, "encrypt_masq_v4_2_encrypted")
int encrypt_masq_v4_2_encrypted_pktgen(struct __ctx_buff *ctx)
{
	return v4_build_packet(ctx);
}

SETUP(PROG_TYPE, "encrypt_masq_v4_2_encrypted")
int encrypt_masq_v4_2_encrypted_setup(struct __ctx_buff *ctx)
{
	ctx->mark = MARK_MAGIC_ENCRYPT;

	return netdev_send_packet(ctx);
}

CHECK(PROG_TYPE, "encrypt_masq_v4_2_encrypted")
int encrypt_masq_v4_2_encrypted_check(const struct __ctx_buff *ctx)
{
	return check(ctx, SRC_POD_V4);
}
