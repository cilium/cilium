// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* make neigh_resolver_available() return true */
#define HAVE_FIB_NEIGH 1
/* assume fib_lookup always returns target oif if available */
#define HAVE_FIB_IFINDEX 1

#include "common.h"
#include "bpf/ctx/skb.h"
#include "linux/bpf.h"

#define CTX_REDIRECT_ENTERED 1001

struct ctx_redirect_recorder {
	const struct __sk_buff *ctx;
	__u32 ifindex;
	__u64 flags;
} redir_recorder = {0};

void reset_redir_recorder(struct ctx_redirect_recorder *r)
{
	r->ctx = 0;
	r->ifindex = 0;
	r->flags = 0XFFFFFFFFFFFFFFFF;
}

#define ctx_redirect mock_ctx_redirect

long mock_ctx_redirect(__maybe_unused const struct __sk_buff *ctx,
		       __maybe_unused __u32 ifindex,
		       __maybe_unused __u64 flags)
{
	redir_recorder.flags = flags;
	redir_recorder.ifindex = ifindex;
	redir_recorder.ctx = ctx;
	return CTX_REDIRECT_ENTERED;
}

#define REDIR_NEIGH_ENTERED 1002

struct redir_neigh_recorder {
	__u32 ifindex;
	struct bpf_redir_neigh *params;
	int plen;
	__u32 flags;
} redir_neigh_recorder = {0};

void reset_redir_neigh_recorder(struct redir_neigh_recorder *r)
{
	r->ifindex = 0;
	r->params = 0;
	r->plen = 0;
	r->flags = 0XFFFFFFFF;
}

#define redirect_neigh mock_redirect_neigh

long mock_redirect_neigh(__maybe_unused int ifindex,
			 __maybe_unused struct bpf_redir_neigh *params,
			 __maybe_unused int plen,
			 __maybe_unused __u32 flags)
{
	redir_neigh_recorder.ifindex = ifindex;
	redir_neigh_recorder.params = params;
	redir_neigh_recorder.plen = plen;
	redir_neigh_recorder.flags = flags;
	return REDIR_NEIGH_ENTERED;
}

#include "lib/dbg.h"
#include "node_config.h"
#include "lib/fib.h"

CHECK("tc", "fib_do_redirect_happy_path")
int test1_check(struct __ctx_buff *ctx)
{
	test_init();

	/* Simulate a successful fib lookup with an output interface.
	 * We expect to enter ctx_redirect with the ifindex provided in the
	 * fib params.
	 */
	TEST("lookup_success", {
		__u32 ifindex_bad  = 0xDEADBEEF;
		__u32 ifindex_good = 0xAAAAAAAA;
		int ret = -1;
		struct bpf_fib_lookup_padded params = {0};
		__s8 ext_err;

		params.l.ifindex = ifindex_good;

		ret = fib_do_redirect(ctx, false, &params, true,
				      BPF_FIB_LKUP_RET_SUCCESS,
				      (int *)&ifindex_bad, &ext_err);
		if (ret != CTX_REDIRECT_ENTERED)
			test_fatal("did not enter ctx_redirect");

		if (redir_recorder.ifindex != ifindex_good)
			test_fatal("expected %x, got %d", ifindex_good,
				   redir_recorder.ifindex);

		if (redir_recorder.ctx != ctx)
			test_fatal("ctx pointer mismatch");

		if (redir_recorder.flags != 0)
			test_fatal("unexpected flags: ");

		reset_redir_recorder(&redir_recorder);
	});

	/* Simulate fib lookup with no neighbor return.
	 * We expect to enter redirect_neigh with the ifindex provided in
	 * fib params and a non-nil bpf_redir_neigh
	 */
	TEST("lookup_no_neigh", {
		__u32 ifindex_bad  = 0xDEADBEEF;
		__u32 ifindex_good = 0xAAAAAAAA;
		int ret = -1;
		struct bpf_fib_lookup_padded params = {0};
		__s8 ext_err;

		params.l.ifindex = ifindex_good;

		if (!neigh_resolver_available())
			test_fatal("expected neigh_resolver_available true");

		ret = fib_do_redirect(ctx, false, &params, true,
				      BPF_FIB_LKUP_RET_NO_NEIGH,
				      (int *)&ifindex_bad, &ext_err);
		if (ret != REDIR_NEIGH_ENTERED)
			test_fatal("did not enter redirect_neigh");

		if (redir_neigh_recorder.ifindex != ifindex_good)
			test_fatal("expected ifindex %x, got %d", ifindex_good,
				   redir_neigh_recorder.ifindex);

		if (!redir_neigh_recorder.params)
			test_fatal("redirect_neigh called with nil params");

		if (redir_neigh_recorder.plen != sizeof(struct bpf_redir_neigh))
			test_fatal("expected plen %d, got %d",
				   sizeof(struct bpf_redir_neigh),
				   redir_neigh_recorder.plen);

		if (redir_neigh_recorder.flags != 0)
			test_fatal("expected flags 0, got %d",
				   redir_neigh_recorder.flags);

		reset_redir_neigh_recorder(&redir_neigh_recorder);
	});

	/* Simulate no fib lookup.
	 * We expect to enter redirect_neigh with the oif provided in the
	 * argument to fib_do_redirect and a nil bpf_redir_neigh structure.
	 */
	TEST("lookup_no_neigh_no_fib", {
		__u32 ifindex_good = 0xBEEFDEAD;
		int ret = -1;
		__s8 ext_err;

		if (!neigh_resolver_available())
			test_fatal("expected neigh_resolver_available true");

		ret = fib_do_redirect(ctx, false, NULL, true,
				      BPF_FIB_LKUP_RET_NO_NEIGH,
				      (int *)&ifindex_good, &ext_err);
		if (ret != REDIR_NEIGH_ENTERED)
			test_fatal("did not enter redirect_neigh");

		if (redir_neigh_recorder.ifindex != ifindex_good)
			test_fatal("expected ifindex %x, got %d", ifindex_good,
				   redir_neigh_recorder.ifindex);

		if (redir_neigh_recorder.params)
			test_fatal("expected nil bpf_redir_neigh");

		if (redir_neigh_recorder.plen != 0)
			test_fatal("expected plen to be 0");

		if (redir_neigh_recorder.flags != 0)
			test_fatal("expected flags 0, got %d",
				   redir_neigh_recorder.flags);

		reset_redir_neigh_recorder(&redir_neigh_recorder);
	});
	test_finish();
}
