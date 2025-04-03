// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include <node_config.h>
#include <lib/static_data.h>

#include "bpf/compiler.h"
#include "lib/common.h"
#include "lib/sock.h"

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

struct sock_common {};

#ifndef TEST_BPF_SOCK_TERM
int bpf_sock_destroy(struct sock_common *sk) __section(".ksyms");
static int BPF_FUNC(seq_write, struct seq_file *m, const void *data,
		    __u32 len);
#endif

static __always_inline
bool matches_v4(const struct sock_term_filter *filter, __sock_cookie cookie)
{
	struct ipv4_revnat_tuple key = {};

	key.address = filter->address.addr4;
	key.port    = filter->port;
	key.cookie  = cookie;

	return map_lookup_elem(&cilium_lb4_reverse_sk, &key);
}

static __always_inline
bool matches_v6(const struct sock_term_filter *filter, __sock_cookie cookie)
{
	struct ipv6_revnat_tuple key = {};

	key.address = filter->address.addr6;
	key.port    = filter->port;
	key.cookie  = cookie;

	return map_lookup_elem(&cilium_lb6_reverse_sk, &key);
}

static __always_inline
int sock_udp_destroy(struct bpf_iter__udp *ctx)
{
	struct sock_term_filter *filter;
	void *sk = ctx->udp_sk;
	bool matches = false;
	__sock_cookie cookie;
	__u32 zero = 0;

	if (!sk)
		return 0;

	filter = map_lookup_elem(&cilium_sock_term_filter, &zero);
	if (!filter)
		return 0;

	cookie = get_socket_cookie(sk);
	switch (filter->address_family) {
	case AF_INET:
		matches = matches_v4(filter, cookie);
		break;
	case AF_INET6:
		matches = matches_v6(filter, cookie);
		break;
	}

	if (!matches)
		return 0;

	if (!bpf_sock_destroy(sk))
		seq_write(ctx->meta->seq, &cookie, sizeof(cookie));

	return 0;
}

__section("iter/udp")
int cil_sock_udp_destroy(struct bpf_iter__udp *ctx)
{
	return sock_udp_destroy(ctx);
}

BPF_LICENSE("Dual BSD/GPL");
