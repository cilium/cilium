// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __CLUSTERMESH_IDENTITY__
#define __CLUSTERMESH_IDENTITY__
#define CLUSTER_ID_MAX 255
#endif

#ifndef __CLUSTERMESH_HELPERS__
#define __CLUSTERMESH_HELPERS__
#define IDENTITY_LEN 8
#define IDENTITY_MAX 255
#endif

#include "common.h"

#include <bpf/ctx/skb.h>
#include <lib/overloadable.h>
#include <lib/clustermesh.h>

#define CLUSTER_LOCAL_IDENTITY 0xAAAA
#define TEST_CLUSTER_ID 0xFFu
#define IDENTITY (0x00000000u | (TEST_CLUSTER_ID << IDENTITY_LEN) | CLUSTER_LOCAL_IDENTITY)

CHECK("tc", "set_and_get_identity")
int check_get_identity(struct __ctx_buff *ctx)
{
	__u32 identity;
	__u32 cluster_id;

	test_init();

	set_identity_mark(ctx, IDENTITY, MARK_MAGIC_IDENTITY);

	identity = get_identity(ctx);
	if (identity != IDENTITY)
		test_fatal("skb->mark should contain identity %u, got %u", IDENTITY, identity);
	cluster_id = extract_cluster_id_from_identity(identity);
	if (cluster_id != TEST_CLUSTER_ID)
		test_fatal("cluster_id should be %u, got %u", TEST_CLUSTER_ID, cluster_id);

	test_finish();
}

CHECK("tc", "set_identity_mark_bits")
int set_identity_mark_bits(struct __ctx_buff *ctx)
{
	test_init();

	set_identity_mark(ctx, 0x0, MARK_MAGIC_IDENTITY);
	set_identity_mark(ctx, 0x0, MARK_MAGIC_OVERLAY);

	if ((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_OVERLAY)
		test_fatal("expected %x got %x", MARK_MAGIC_OVERLAY, ctx->mark);

	set_identity_mark(ctx, 0x0, 0x000);
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) != 0)
		test_fatal("expected %x got %x", 0, ctx->mark);

	set_identity_mark(ctx, 0x0, MARK_MAGIC_HOST_MASK);
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) != MARK_MAGIC_HOST_MASK)
		test_fatal("expected %x got %x", MARK_MAGIC_HOST_MASK, ctx->mark);

	test_finish();
}

CHECK("tc", "set_and_get_cluster_id")
int check_ctx_get_cluster_id_mark(struct __ctx_buff *ctx)
{
	__u32 cluster_id;

	test_init();

	ctx_set_cluster_id_mark(ctx, TEST_CLUSTER_ID);

	cluster_id = ctx_get_cluster_id_mark(ctx);
	if (cluster_id != TEST_CLUSTER_ID)
		test_fatal("cluster_id should be %u, got %u", TEST_CLUSTER_ID, cluster_id);

	test_finish();
}
