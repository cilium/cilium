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

struct sock_common {};

#ifndef BPF_TEST
int bpf_sock_destroy(struct sock_common *sk) __section(".ksyms");
static int BPF_FUNC(seq_write, struct seq_file *m, const void *data,
		    __u32 len);
#endif

#ifndef BPF_TEST
/* Enough of the kernel's socket types to reach sk_state, with the field
 * offsets resolved against the running kernel's BTF at load time.
 */
struct sock_common___local {
	__u8 skc_state;
} __attribute__((preserve_access_index));

struct sock___local {
	struct sock_common___local __sk_common;
} __attribute__((preserve_access_index));

struct inet_sock___local {
	struct sock___local sk;
} __attribute__((preserve_access_index));

struct udp_sock___local {
	struct inet_sock___local inet;
} __attribute__((preserve_access_index));

/* A UDP socket carries a TCP state: udp_connect() sets TCP_ESTABLISHED and
 * __udp_disconnect() clears it back to TCP_CLOSE. Asking the socket is what
 * the netlink destroyer did before v1.19, where MatchSocket() compared the
 * socket's own destination, and it is why unconnected sockets were exempt
 * then.
 */
static __always_inline
bool udp_sock_is_connected(void *sk)
{
	struct udp_sock___local *udp = sk;

	return udp->inet.sk.__sk_common.skc_state == BPF_TCP_ESTABLISHED;
}
#endif

static __always_inline
bool matches_v4(__sock_cookie cookie)
{
	struct ipv4_revnat_tuple key = { };

	key.address = cilium_sock_term_filter.address.addr4;
	key.port    = bpf_htons(cilium_sock_term_filter.port);
	key.cookie  = cookie;

	return map_lookup_elem(&cilium_lb4_reverse_sk, &key);
}

static __always_inline
bool matches_v6(__sock_cookie cookie)
{
	struct ipv6_revnat_tuple key = { };

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

	if (!matches_v4(cookie))
		return 0;

	/* An entry in cilium_lb4_reverse_sk is not proof of a connection:
	 * cil_sock4_sendmsg writes one for every unconnected sendto() to a
	 * Service, so that cil_sock4_recvmsg can un-translate the reply.
	 * Destroying such a socket releases its local port, and the next
	 * sendto() autobinds to a different one under an application that
	 * made no call of its own.
	 */
	if (!udp_sock_is_connected(sk))
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

	if (!matches_v4(cookie))
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

	if (!matches_v6(cookie))
		return 0;

	/* See sock_udp_destroy_v4(). */
	if (!udp_sock_is_connected(sk))
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

	if (!matches_v6(cookie))
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
