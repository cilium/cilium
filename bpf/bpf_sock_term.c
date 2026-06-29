// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include <node_config.h>
#include <lib/static_data.h>

#include "bpf/compiler.h"
#include "lib/endian.h"
#include "lib/sock.h"
#include "lib/sock_term.h"

struct sock_term_filter cilium_sock_term_filter;

/* Stub out types that would normally be found in vmlinux.h to satisfy BTF type
 * checks
 */
struct seq_file {};

struct bpf_iter_meta {
	struct seq_file *seq;
};

struct bpf_iter__udp {
	struct bpf_iter_meta *meta;
	void *udp_sk;
};

struct bpf_iter__tcp {
	struct bpf_iter_meta *meta;
	void *tcp_sk;
};

struct in6_addr_stub {
	union {
		__u8 u6_addr8[16];
		__be32 u6_addr32[4];
	} in6_u;
};

struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	union {
		struct {
			struct in6_addr_stub skc_v6_daddr;
			struct in6_addr_stub skc_v6_rcv_saddr;
		};
	};
} __attribute__((preserve_access_index));

#ifndef BPF_TEST
int bpf_sock_destroy(struct sock_common *sk) __section(".ksyms");
static int BPF_FUNC(seq_write, struct seq_file *m, const void *data,
		    __u32 len);
#endif

static __always_inline bool matches_v4(void *sk)
{
	struct sock_common *skc = sk;

	return skc &&
	       skc->skc_daddr == cilium_sock_term_filter.address.addr4 &&
	       skc->skc_dport == bpf_htons(cilium_sock_term_filter.port);
}

static __always_inline bool matches_v6(void *sk)
{
	struct sock_common *skc = sk;

	return skc &&
	       !memcmp(&skc->skc_v6_daddr,
		       &cilium_sock_term_filter.address.addr6,
		       sizeof(union v6addr)) &&
	       skc->skc_dport == bpf_htons(cilium_sock_term_filter.port);
}

static __always_inline
int sock_udp_destroy_v4(struct bpf_iter__udp *ctx)
{
	void *sk = ctx->udp_sk;

	if (!sk)
		return 0;

	if (!matches_v4(sk))
		return 0;

	if (!bpf_sock_destroy(sk)) {
		__sock_cookie cookie = get_socket_cookie(sk);
		seq_write(ctx->meta->seq, &cookie, sizeof(cookie));
	}

	return 0;
}

static __always_inline
int sock_tcp_destroy_v4(struct bpf_iter__tcp *ctx __maybe_unused)
{
	void *sk = ctx->tcp_sk;

	if (!sk)
		return 0;

	if (!matches_v4(sk))
		return 0;

	if (!bpf_sock_destroy(sk)) {
		__sock_cookie cookie = get_socket_cookie(sk);
		seq_write(ctx->meta->seq, &cookie, sizeof(cookie));
	}

	return 0;
}

static __always_inline
int sock_udp_destroy_v6(struct bpf_iter__udp *ctx)
{
	void *sk = ctx->udp_sk;

	if (!sk)
		return 0;

	if (!matches_v6(sk))
		return 0;

	if (!bpf_sock_destroy(sk)) {
		__sock_cookie cookie = get_socket_cookie(sk);
		seq_write(ctx->meta->seq, &cookie, sizeof(cookie));
	}

	return 0;
}

static __always_inline
int sock_tcp_destroy_v6(struct bpf_iter__tcp *ctx __maybe_unused)
{
	void *sk = ctx->tcp_sk;

	if (!sk)
		return 0;

	if (!matches_v6(sk))
		return 0;

	if (!bpf_sock_destroy(sk)) {
		__sock_cookie cookie = get_socket_cookie(sk);
		seq_write(ctx->meta->seq, &cookie, sizeof(cookie));
	}

	return 0;
}

__section("iter/udp")
int cil_sock_udp_destroy_v4(struct bpf_iter__udp *ctx)
{
	return sock_udp_destroy_v4(ctx);
}

__section("iter/tcp")
int cil_sock_tcp_destroy_v4(struct bpf_iter__tcp *ctx)
{
	return sock_tcp_destroy_v4(ctx);
}

__section("iter/udp")
int cil_sock_udp_destroy_v6(struct bpf_iter__udp *ctx)
{
	return sock_udp_destroy_v6(ctx);
}

__section("iter/tcp")
int cil_sock_tcp_destroy_v6(struct bpf_iter__tcp *ctx)
{
	return sock_tcp_destroy_v6(ctx);
}

BPF_LICENSE("Dual BSD/GPL");
