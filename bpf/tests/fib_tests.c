// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#define ENABLE_IPV4		      1
#define ENABLE_IPV6		      1
#define SKIP_ICMPV6_HOPLIMIT_HANDLING 1
#include "common.h"

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

struct fib_lookup_recorder {
	__u32 flags;
} fib_lookup_recorder = {0};

void reset_fib_lookup_recorder(struct fib_lookup_recorder *r)
{
	r->flags = 0;
}

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(void *ctx __maybe_unused,
		     struct bpf_fib_lookup *params __maybe_unused,
		     int plen __maybe_unused, __u32 flags __maybe_unused)
{
	fib_lookup_recorder.flags = flags;
	return 0;
}

#include "lib/dbg.h"
#include <bpf/config/global.h>
#include <bpf/config/node.h>
#include "lib/fib.h"

ASSIGN_CONFIG(bool, supports_fib_lookup_skip_neigh, true)

CHECK("tc", "fib_do_redirect_happy_path")
int test1_check(struct __ctx_buff *ctx)
{
	test_init();

	/* Simulate a successful fib lookup with an output interface.
	 * We expect to enter ctx_redirect with the provided ifindex.
	 */
	TEST("lookup_success", {
		__u32 ifindex_good = 0xAAAAAAAA;
		int ret = -1;
		struct bpf_fib_lookup_padded params = {0};
		__s8 ext_err;

		ret = fib_do_redirect(ctx, false, &params, true,
				      BPF_FIB_LKUP_RET_SUCCESS,
				      ifindex_good, &ext_err);
		if (ret != REDIR_NEIGH_ENTERED)
			test_fatal("did not enter ctx_redirect_neigh");

		if (redir_neigh_recorder.ifindex != ifindex_good)
			test_fatal("expected %x, got %d", ifindex_good,
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

	/* Simulate fib lookup with no neighbor return.
	 * We expect to enter redirect_neigh with provided ifindex
	 * and a non-nil bpf_redir_neigh.
	 */
	TEST("lookup_no_neigh", {
		__u32 ifindex_good = 0xAAAAAAAA;
		int ret = -1;
		struct bpf_fib_lookup_padded params = {0};
		__s8 ext_err;

		if (!neigh_resolver_available())
			test_fatal("expected neigh_resolver_available true");

		ret = fib_do_redirect(ctx, false, &params, true,
				      BPF_FIB_LKUP_RET_NO_NEIGH,
				      ifindex_good, &ext_err);
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
				      ifindex_good, &ext_err);
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

CHECK("tc", "fib_redirect*_fib_lookup_flags")
int test2_check(struct __ctx_buff *ctx)
{
	test_init();

	TEST("fib_redirect", {
		struct bpf_fib_lookup_padded params = { 0 };
		int oif = 0;
		__s8 ext_err;

		if (!neigh_resolver_available())
			test_fatal("expected neigh_resolver_available true");

		fib_redirect(ctx, false, &params, true, &ext_err, &oif);

		if (fib_lookup_recorder.flags != BPF_FIB_LOOKUP_SKIP_NEIGH)
			test_fatal("expected flags %x, got %d",
				   BPF_FIB_LOOKUP_SKIP_NEIGH,
				   fib_lookup_recorder.flags);

		reset_fib_lookup_recorder(&fib_lookup_recorder);
	});

	TEST("fib_redirect_v4", {
		struct iphdr hdr = { 0 };
		int oif = 0;
		__s8 ext_err;

		if (!neigh_resolver_available())
			test_fatal("expected neigh_resolver_available true");

		fib_redirect_v4(ctx, 0, &hdr, true, true, &ext_err, &oif, 0);

		if (fib_lookup_recorder.flags != BPF_FIB_LOOKUP_SKIP_NEIGH)
			test_fatal("expected flags %x, got %d",
				   BPF_FIB_LOOKUP_SKIP_NEIGH,
				   fib_lookup_recorder.flags);

		reset_fib_lookup_recorder(&fib_lookup_recorder);
	});

	TEST("fib_redirect_v6", {
		struct ipv6hdr hdr6 = { 0 };
		int oif = 0;
		__s8 ext_err;

		if (!neigh_resolver_available())
			test_fatal("expected neigh_resolver_available true");

		fib_redirect_v6(ctx, 0, &hdr6, true, true, &ext_err, &oif, 0);

		if (fib_lookup_recorder.flags != BPF_FIB_LOOKUP_SKIP_NEIGH)
			test_fatal("expected flags %x, got %d",
				   BPF_FIB_LOOKUP_SKIP_NEIGH,
				   fib_lookup_recorder.flags);

		reset_fib_lookup_recorder(&fib_lookup_recorder);
	});

	test_finish();
}
