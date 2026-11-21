// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>

static __u64 mock_full_len;
static __u32 mock_gso_size;

static __always_inline __maybe_unused __u64
mock_ctx_full_len(const struct __sk_buff *ctx __maybe_unused)
{
	return mock_full_len;
}

static __always_inline __maybe_unused __u32
mock_ctx_gso_size(const struct __sk_buff *ctx __maybe_unused)
{
	return mock_gso_size;
}

#define ctx_full_len mock_ctx_full_len
#define ctx_gso_size mock_ctx_gso_size

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
	__u16 tot_len;
	int result;
} fib_lookup_recorder = {0};

void reset_fib_lookup_recorder(struct fib_lookup_recorder *r)
{
	r->flags = 0;
	r->tot_len = 0;
	r->result = BPF_FIB_LKUP_RET_SUCCESS;
}

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(void *ctx __maybe_unused,
		     const struct bpf_fib_lookup *params __maybe_unused,
		     int plen __maybe_unused, __u32 flags __maybe_unused)
{
	fib_lookup_recorder.flags = flags;
	fib_lookup_recorder.tot_len = params->tot_len;
	return fib_lookup_recorder.result;
}

#include "lib/dbg.h"
#include <bpf/config/global.h>
#include <bpf/config/node.h>
#include "lib/fib.h"

ASSIGN_CONFIG(bool, enable_ipv4, true)
ASSIGN_CONFIG(bool, enable_ipv6, true)
ASSIGN_CONFIG(bool, supports_fib_lookup_skip_neigh, true)

CHECK(PROG_TYPE, "fib_do_redirect_happy_path")
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

CHECK(PROG_TYPE, "fib_redirect*_fib_lookup_flags")
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

	TEST("fib_redirect_frag_needed", {
		struct bpf_fib_lookup_padded params = { 0 };
		int oif = 0;
		__s8 ext_err = 0;
		int ret;

		fib_lookup_recorder.result = BPF_FIB_LKUP_RET_FRAG_NEEDED;
		ret = fib_redirect(ctx, false, &params, true, &ext_err, &oif);
		reset_fib_lookup_recorder(&fib_lookup_recorder);

		if (ret != DROP_FRAG_NEEDED)
			test_fatal("expected DROP_FRAG_NEEDED, got %d", ret);
		if (ext_err != BPF_FIB_LKUP_RET_FRAG_NEEDED)
			test_fatal("expected FRAG_NEEDED ext_err, got %d", ext_err);
	});

	TEST("ip_wire_len_header_and_context", {
		struct iphdr hdr = { 0 };
		struct ipv6hdr hdr6 = { 0 };
		const __u32 header_len = 1400;
		const __u32 context_len = 1600;
		const int l3_off = ETH_HLEN;

		hdr.tot_len = bpf_htons(header_len);
		hdr6.payload_len = bpf_htons(header_len - sizeof(hdr6));
		mock_full_len = context_len;

		if (ipv4_wire_len(ctx, &hdr, l3_off) != header_len)
			test_fatal("IPv4 wire length did not prefer the header");
		if (ipv6_wire_len(ctx, &hdr6, l3_off) != header_len)
			test_fatal("IPv6 wire length did not prefer the header");

		hdr.tot_len = 0;
		hdr6.payload_len = 0;
		if (ipv4_wire_len(ctx, &hdr, l3_off) != context_len - l3_off)
			test_fatal("IPv4 zero length did not fall back to the context");
		if (ipv6_wire_len(ctx, &hdr6, l3_off) != context_len - l3_off)
			test_fatal("IPv6 zero length did not fall back to the context");

		mock_full_len = 0;
	});

	/* Preserve the skb helper contract for GSO/BIG TCP: a zero tot_len makes
	 * the kernel validate the skb with is_skb_forwardable(), which honors GSO.
	 */
	TEST("fib_redirect_skb_gso_tot_len", {
		struct iphdr hdr = { 0 };
		struct ipv6hdr hdr6 = { 0 };
		__u16 v4_tot_len;
		__u16 v6_tot_len;
		int oif = 0;
		__s8 ext_err;

		hdr.ihl = 5;
		hdr.tot_len = bpf_htons(9000);
		hdr.ttl = 64;
		hdr.protocol = IPPROTO_TCP;
		hdr6.payload_len = bpf_htons(8960);
		hdr6.nexthdr = IPPROTO_TCP;
		hdr6.hop_limit = 64;

		mock_gso_size = 1400;

		fib_redirect_v4(ctx, 0, &hdr, true, true, &ext_err, &oif, 0);
		v4_tot_len = fib_lookup_recorder.tot_len;
		reset_fib_lookup_recorder(&fib_lookup_recorder);

		fib_redirect_v6(ctx, 0, &hdr6, true, true, &ext_err, &oif, 0);
		v6_tot_len = fib_lookup_recorder.tot_len;
		reset_fib_lookup_recorder(&fib_lookup_recorder);
		mock_gso_size = 0;

		if (v4_tot_len != 0)
			test_fatal("IPv4 skb FIB tot_len must be zero, got %u", v4_tot_len);
		if (v6_tot_len != 0)
			test_fatal("IPv6 skb FIB tot_len must be zero, got %u", v6_tot_len);
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
