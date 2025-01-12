/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

static __always_inline __maybe_unused
__sock_cookie sock_local_cookie(struct bpf_sock_addr *ctx)
{
#ifdef TEST_BPF_SOCK
	/* Some BPF tests run bpf_sock.c code in XDP context.
	 * Allow them to pass the verifier.
	 */
	return ctx->protocol == IPPROTO_TCP ? get_prandom_u32() : 0;
#else
	return get_socket_cookie(ctx);
#endif
}

