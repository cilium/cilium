// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "bpf/builtins.h"
#include "common.h"
#include "bpf/compiler.h"
#include "bpf/types_mapper.h"
#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#define bpf_sock_destroy   mock_bpf_sock_destroy
#define seq_write	   mock_bpf_seq_write
#define get_socket_cookie  mock_get_socket_cookie

struct sock_common;
struct seq_file;
struct sock;

static int destroys;

static __always_inline int
mock_bpf_sock_destroy(struct sock_common *sk __maybe_unused)
{
	destroys++;

	return 0;
}

static char write_data[sizeof(__sock_cookie)];
static __u32 write_len;

static __always_inline int
mock_bpf_seq_write(struct seq_file *m __maybe_unused, const void *data, __u32 len)
{
	write_len = len;

	if (len > sizeof(__sock_cookie))
		return 0;

	memcpy(write_data, data, len);

	return 0;
}

static __sock_cookie current_cookie;

static __always_inline __sock_cookie mock_get_socket_cookie(void *ctx __maybe_unused)
{
	return current_cookie;
}

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1

#include "lib/socket.h"

#include "bpf_sock_term.c"

const __sock_cookie no_match_cookie4 = 200;
const __sock_cookie no_match_cookie6 = 201;
const __sock_cookie match_cookie4 = 100;
const __sock_cookie match_cookie6 = 101;
const __be32 match_addr4 = 0xDEADBEEF;
const union v6addr match_addr6 = { .d1 = 0x1, .d2 = 0x2 };
const __u16 match_port = 8080;

static __always_inline int insert4(struct ipv4_revnat_tuple *key)
{
	struct ipv4_revnat_entry val = {};

	return map_update_elem(&cilium_lb4_reverse_sk, key, &val, 0);
}

static __always_inline int insert6(struct ipv6_revnat_tuple *key)
{
	struct ipv6_revnat_entry val = {};

	return map_update_elem(&cilium_lb6_reverse_sk, key, &val, 0);
}

static __always_inline int setup(void)
{
	struct ipv4_revnat_tuple key4 = {};
	struct ipv6_revnat_tuple key6 = {};

	key4.address = match_addr4;
	key4.port = bpf_htons(match_port);
	key4.cookie = match_cookie4;

	key6.address = match_addr6;
	key6.port = bpf_htons(match_port);
	key6.cookie = match_cookie6;

	if (insert4(&key4))
		return 1;

	if (insert6(&key6))
		return 1;

	return 0;
}

static __always_inline void set_filter(struct sock_term_filter *filter)
{
	memcpy(&cilium_sock_term_filter, filter, sizeof(*filter));
}

static __always_inline void reset(__sock_cookie cookie)
{
	current_cookie = cookie;
	destroys = 0;
	memset(write_data, 0, sizeof(__sock_cookie));
	write_len = 0;
}

CHECK("xdp", "sock_terminate")
int test_sock_terminate(__maybe_unused struct xdp_md *ctx)
{
	struct sock_term_filter filter4 = {
		.address = {
			.addr4 = match_addr4,
		},
		.address_family = AF_INET,
		.port = match_port,
	};
	struct sock_term_filter filter6 = {
		.address = {
			.addr6 = match_addr6,
		},
		.address_family = AF_INET6,
		.port = match_port,
	};
	struct bpf_iter__udp iter_ctx_udp;
	struct bpf_iter__tcp iter_ctx_tcp;
	struct bpf_iter_meta meta;
	struct seq_file seq;
	int sk;

	iter_ctx_udp.meta = &meta;
	iter_ctx_udp.udp_sk = &sk;
	iter_ctx_tcp.meta = &meta;
	iter_ctx_tcp.tcp_sk = &sk;
	meta.seq = &seq;

	test_init();
	assert(!setup());

	/* IPv4 tests */
	set_filter(&filter4);

	/* UDP */

	/* Don't destroy the socket if its cookie isn't in
	 * cilium_lb4_reverse_sk.
	 */
	reset(no_match_cookie4);
	sock_udp_destroy_v4(&iter_ctx_udp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Destroy the socket if its cookie is in cilium_lb4_reverse_sk. */
	reset(match_cookie4);
	sock_udp_destroy_v4(&iter_ctx_udp);
	assert(destroys == 1);
	assert(write_len == sizeof(__sock_cookie));
	assert(*((__sock_cookie *)write_data) == match_cookie4);

	/* TCP */

	/* Don't destroy the socket if its cookie isn't in
	 * cilium_lb4_reverse_sk.
	 */
	reset(no_match_cookie4);
	sock_tcp_destroy_v4(&iter_ctx_tcp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Destroy the socket if its cookie is in cilium_lb4_reverse_sk. */
	reset(match_cookie4);
	sock_tcp_destroy_v4(&iter_ctx_tcp);
	assert(destroys == 1);
	assert(write_len == sizeof(__sock_cookie));
	assert(*((__sock_cookie *)write_data) == match_cookie4);

	/* IPv6 tests */
	set_filter(&filter6);

	/* UDP */

	/* Don't destroy the socket if its cookie isn't in
	 * cilium_lb6_reverse_sk.
	 */
	reset(no_match_cookie6);
	sock_udp_destroy_v6(&iter_ctx_udp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Destroy the socket if its cookie is in cilium_lb6_reverse_sk. */
	reset(match_cookie6);
	sock_udp_destroy_v6(&iter_ctx_udp);
	assert(destroys == 1);
	assert(write_len == sizeof(__sock_cookie));
	assert(*((__sock_cookie *)write_data) == match_cookie6);

	/* TCP */

	/* Don't destroy the socket if its cookie isn't in
	 * cilium_lb6_reverse_sk.
	 */
	reset(no_match_cookie6);
	sock_tcp_destroy_v6(&iter_ctx_tcp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Destroy the socket if its cookie is in cilium_lb6_reverse_sk. */
	reset(match_cookie6);
	sock_tcp_destroy_v6(&iter_ctx_tcp);
	assert(destroys == 1);
	assert(write_len == sizeof(__sock_cookie));
	assert(*((__sock_cookie *)write_data) == match_cookie6);

	test_finish();
}
