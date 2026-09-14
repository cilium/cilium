// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>
#include <linux/in6.h>

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

/* Enough of the kernel's socket types to reach the destination address and
 * port. Outside the unit test the field offsets are resolved against the
 * running kernel's BTF at load time; the test builds the socket itself, so it
 * keeps the layout declared here.
 */
#ifdef BPF_TEST
# define __sock_btf
#else
# define __sock_btf __attribute__((preserve_access_index))
#endif

struct sock_common {
	__be32 skc_daddr;
	__be16 skc_dport;
	struct in6_addr skc_v6_daddr;
} __sock_btf;

struct sock {
	struct sock_common __sk_common;
} __sock_btf;

#ifndef BPF_TEST
int bpf_sock_destroy(struct sock_common *sk) __section(".ksyms");
static int BPF_FUNC(seq_write, struct seq_file *m, const void *data,
		    __u32 len);
#endif

static __always_inline
bool matches_v4(void *sk, __sock_cookie cookie)
{
	struct ipv4_revnat_tuple key = { };
	struct sock *s = sk;

	/* Ensure that sk is still connected to the backend. */
	if (s->__sk_common.skc_daddr != cilium_sock_term_filter.address.addr4 ||
	    s->__sk_common.skc_dport != bpf_htons(cilium_sock_term_filter.port))
		return false;

	/* Ensure that sk was connected to the backend via a service VIP. */
	key.address = cilium_sock_term_filter.address.addr4;
	key.port    = bpf_htons(cilium_sock_term_filter.port);
	key.cookie  = cookie;

	return map_lookup_elem(&cilium_lb4_reverse_sk, &key);
}

static __always_inline
bool matches_v6(void *sk, __sock_cookie cookie)
{
	struct ipv6_revnat_tuple key = { };
	struct sock *s = sk;

	/* Ensure that sk is still connected to the backend. */
	if (s->__sk_common.skc_dport != bpf_htons(cilium_sock_term_filter.port) ||
	    s->__sk_common.skc_v6_daddr.s6_addr32[0] != cilium_sock_term_filter.address.addr6.p1 ||
	    s->__sk_common.skc_v6_daddr.s6_addr32[1] != cilium_sock_term_filter.address.addr6.p2 ||
	    s->__sk_common.skc_v6_daddr.s6_addr32[2] != cilium_sock_term_filter.address.addr6.p3 ||
	    s->__sk_common.skc_v6_daddr.s6_addr32[3] != cilium_sock_term_filter.address.addr6.p4)
		return false;

	/* Ensure that sk was connected to the backend via a service VIP. */
	key.address = cilium_sock_term_filter.address.addr6;
	key.port    = bpf_htons(cilium_sock_term_filter.port);
	key.cookie  = cookie;

	return map_lookup_elem(&cilium_lb6_reverse_sk, &key);
}

static __always_inline
int sock_udp_destroy_v4(struct bpf_iter__udp *ctx)
{
	void *sk = ctx->udp_sk;
	__sock_cookie cookie;

	if (!sk)
		return 0;

	cookie = get_socket_cookie(sk);

	if (!matches_v4(sk, cookie))
		return 0;

	if (!bpf_sock_destroy(sk))
		seq_write(ctx->meta->seq, &cookie, sizeof(cookie));

	return 0;
}

static __always_inline
int sock_tcp_destroy_v4(struct bpf_iter__tcp *ctx)
{
	void *sk = ctx->tcp_sk;
	__sock_cookie cookie;

	if (!sk)
		return 0;

	cookie = get_socket_cookie(sk);

	if (!matches_v4(sk, cookie))
		return 0;

	if (!bpf_sock_destroy(sk))
		seq_write(ctx->meta->seq, &cookie, sizeof(cookie));

	return 0;
}

static __always_inline
int sock_udp_destroy_v6(struct bpf_iter__udp *ctx)
{
	void *sk = ctx->udp_sk;
	__sock_cookie cookie;

	if (!sk)
		return 0;

	cookie = get_socket_cookie(sk);

	if (!matches_v6(sk, cookie))
		return 0;

	if (!bpf_sock_destroy(sk))
		seq_write(ctx->meta->seq, &cookie, sizeof(cookie));

	return 0;
}

static __always_inline
int sock_tcp_destroy_v6(struct bpf_iter__tcp *ctx)
{
	void *sk = ctx->tcp_sk;
	__sock_cookie cookie;

	if (!sk)
		return 0;

	cookie = get_socket_cookie(sk);

	if (!matches_v6(sk, cookie))
		return 0;

	if (!bpf_sock_destroy(sk))
		seq_write(ctx->meta->seq, &cookie, sizeof(cookie));

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
