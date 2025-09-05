// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4			1
#define ENABLE_WIREGUARD		1
#define ENABLE_IDENTITY_MARK		1

#define SRC_POD_V4			v4_pod_one
#define DST_POD_V4			v4_pod_one_on_node_two
#define DST_POD_CIDR_V4			v4_pod_cidr_on_node_two

#define SRC_POD_SEC_IDENTITY		(CIDR_IDENTITY_RANGE_START - 2)
#define DST_POD_SEC_IDENTITY		(CIDR_IDENTITY_RANGE_START - 3)

#define SRC_NODE_V4			v4_node_one
#define DST_NODE_V4			v4_node_two

#define ENCRYPT_KEY			0xFF

#include "bpf_host.c"

#include "lib/ipcache.h"

#define TO_NETDEV 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
	},
};

static __always_inline
int v4_build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
				      SRC_POD_V4, DST_POD_V4);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Validate that if the destination endpoint is being torn down (and
 * its ipcache entry is missing), then the corresponding PodCIDR entry
 * is still sufficient to apply encryption for a pod-to-pod packet.
 */
PKTGEN("tc", "wg_v4_1_missing_dst")
int wg_v4_1_missing_dst_pktgen(struct __ctx_buff *ctx)
{
	return v4_build_packet(ctx);
}

SETUP("tc", "wg_v4_1_missing_dst")
int wg_v4_1_missing_dst_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry_with_mask_size(DST_POD_CIDR_V4, 0, WORLD_ID,
					    DST_NODE_V4, ENCRYPT_KEY,
					    v4_pod_cidr_size);

	set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_IDENTITY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "wg_v4_1_missing_dst")
int wg_v4_1_missing_dst_check(const struct __ctx_buff *ctx)
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
	assert(*status_code == CTX_ACT_REDIRECT);

	test_finish();
}

/* Validate the behavior for a terminating source endpoint.
 *
 * First we test *with* the sec identity in the mark. This should be
 * sufficient to trigger encryption, even if the endpoint's ipcache entry
 * is not available.
 */
PKTGEN("tc", "wg_v4_2_src_mark")
int wg_v4_2_src_mark_pktgen(struct __ctx_buff *ctx)
{
	return v4_build_packet(ctx);
}

SETUP("tc", "wg_v4_2_src_mark")
int wg_v4_2_src_mark_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(DST_POD_V4, 0, DST_POD_SEC_IDENTITY,
			     DST_NODE_V4, ENCRYPT_KEY);
	ipcache_v4_add_entry_with_mask_size(DST_POD_CIDR_V4, 0, WORLD_ID,
					    DST_NODE_V4, ENCRYPT_KEY,
					    v4_pod_cidr_size);

	set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_IDENTITY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "wg_v4_2_src_mark")
int wg_v4_2_src_mark_check(const struct __ctx_buff *ctx)
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
	assert(*status_code == CTX_ACT_REDIRECT);

	test_finish();
}

/* Now test *without* the identity in the mark. This should *not* trigger
 * encryption:
 */
PKTGEN("tc", "wg_v4_3_no_src_mark")
int wg_v4_3_no_src_mark_pktgen(struct __ctx_buff *ctx)
{
	return v4_build_packet(ctx);
}

SETUP("tc", "wg_v4_3_no_src_mark")
int wg_v4_3_no_src_mark_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(DST_POD_V4, 0, DST_POD_SEC_IDENTITY,
			     DST_NODE_V4, ENCRYPT_KEY);
	ipcache_v4_add_entry_with_mask_size(DST_POD_CIDR_V4, 0, WORLD_ID,
					    DST_NODE_V4, ENCRYPT_KEY,
					    v4_pod_cidr_size);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "wg_v4_3_no_src_mark")
int wg_v4_3_no_src_mark_check(const struct __ctx_buff *ctx)
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

	test_finish();
}

/* Finally test without the mark, but with the endpoint's ipcache entry: */
PKTGEN("tc", "wg_v4_4_no_src_mark_with_src_entry")
int wg_v4_4_no_src_mark_with_src_entry_pktgen(struct __ctx_buff *ctx)
{
	return v4_build_packet(ctx);
}

SETUP("tc", "wg_v4_4_no_src_mark_with_src_entry")
int wg_v4_4_no_src_mark_with_src_entry_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(SRC_POD_V4, 0, SRC_POD_SEC_IDENTITY,
			     0, ENCRYPT_KEY);
	ipcache_v4_add_entry(DST_POD_V4, 0, DST_POD_SEC_IDENTITY,
			     DST_NODE_V4, ENCRYPT_KEY);
	ipcache_v4_add_entry_with_mask_size(DST_POD_CIDR_V4, 0, WORLD_ID,
					    DST_NODE_V4, ENCRYPT_KEY,
					    v4_pod_cidr_size);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "wg_v4_4_no_src_mark_with_src_entry")
int wg_v4_4_no_src_mark_with_src_entry_check(const struct __ctx_buff *ctx)
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
	assert(*status_code == CTX_ACT_REDIRECT);

	test_finish();
}
