// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "encryption_helpers_ipsec.h"

struct ctx_redirect_recorder {
	int ifindex;
	__u32 flags;
} rec;

int mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused, int ifindex, __u32 flags)
{
	rec.flags = flags;
	rec.ifindex = ifindex;
	return CTX_ACT_REDIRECT;
}

#define ctx_redirect mock_ctx_redirect

#include "lib/bpf_host.h"

#include "node_config.h"

#include "tests/lib/ipcache.h"
#include "tests/lib/ipsec.h"
#include "tests/lib/node.h"

#include "scapy.h"

ASSIGN_CONFIG(__u32, cilium_host_ifindex, 10);

static __always_inline int
pktgen(struct __ctx_buff *ctx, bool ipv4)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	if (ipv4) {
		BUF_DECL(V4_IPSEC, v4_ipsec);
		BUILDER_PUSH_BUF(builder, V4_IPSEC);
	} else {
		BUF_DECL(V6_IPSEC, v6_ipsec);
		BUILDER_PUSH_BUF(builder, V6_IPSEC);
	}

	pktgen__finish(&builder);

	return 0;
}

static __always_inline
int check(struct __ctx_buff *ctx, bool ipv4)
{
	test_init();

	__be16 proto = ctx_get_protocol(ctx);

	/* Without node entry, do nothing. */
	assert(do_decrypt(ctx, proto) == DROP_NO_NODE_ID);
	assert(ctx->mark == 0);

	if (ipv4)
		node_v4_add_entry(SOURCE_NODE_IP, SOURCE_NODE_ID, TARGET_SPI);
	else
		node_v6_add_entry((union v6addr *)SOURCE_NODE_IP_6, SOURCE_NODE_ID, TARGET_SPI);

	/* First pass with a non-marked encrypted packet, mark and pass to stack. */
	assert(do_decrypt(ctx, proto) == CTX_ACT_OK);
	assert(ctx_is_decrypt(ctx));

	/* With a marked packet, let's redirect to cilium_host. */
	assert(do_decrypt(ctx, proto) == CTX_ACT_REDIRECT);
	assert(ctx->mark == 0);
	assert(rec.ifindex == (int)CONFIG(cilium_host_ifindex));
	assert(rec.flags == 0);

	/* With a wrong protocol we don't do anything. */
	assert(do_decrypt(ctx, bpf_htons(IPPROTO_UDP)) == CTX_ACT_OK);
	assert(ctx->mark == 0);

	test_finish();
}

PKTGEN("tc", "do_decrypt4")
static __always_inline int
do_decrypt4_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, true);
}

CHECK("tc", "do_decrypt4")
int do_decrypt4_check(struct __ctx_buff *ctx)
{
	return check(ctx, true);
}

PKTGEN("tc", "do_decrypt6")
static __always_inline int
do_decrypt6_pktgen(struct __ctx_buff *ctx)
{
	return pktgen(ctx, false);
}

CHECK("tc", "do_decrypt6")
int do_decrypt6_check(struct __ctx_buff *ctx)
{
	return check(ctx, false);
}

CHECK("tc", "ctx_is_encrypt_success")
int check2(struct __ctx_buff *ctx)
{
	test_init();

	assert(!ctx_is_encrypt(ctx));

	ctx->mark = MARK_MAGIC_ENCRYPT;

	assert(ctx_is_encrypt(ctx));

	test_finish();
}

CHECK("tc", "ctx_is_decrypt_success")
int check3(struct __ctx_buff *ctx)
{
	test_init();

	assert(!ctx_is_decrypt(ctx));

	ctx->mark = MARK_MAGIC_DECRYPT;

	assert(ctx_is_decrypt(ctx));

	test_finish();
}
