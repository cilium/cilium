/*
 *  Copyright (C) 2019 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <node_config.h>
#include <netdev_config.h>

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/lb.h"

#define CONNECT_REJECT	0
#define CONNECT_PROCEED	1

/* Hack due to missing narrow ctx access. */
static __always_inline __maybe_unused __be16
ctx_get_port(struct bpf_sock_addr *ctx)
{
	volatile __u32 dport = ctx->user_port;
	return (__be16)dport;
}

static __always_inline __maybe_unused
void ctx_set_port(struct bpf_sock_addr *ctx, __be16 dport)
{
	ctx->user_port = (__u32)dport;
}

static __always_inline __maybe_unused
__u64 sock_pick_rand(struct bpf_sock_addr *ctx)
{
#ifdef HAVE_GET_SOCK_COOKIE
	return get_socket_cookie(ctx);
#else
	/* Given this is for the entire connection, we can pick one
	 * randomly. If we actually support weighted selection one
	 * day, this needs slight adjustment. prandom() might break
	 * down on unconnected UDP depending on the workload, hence
	 * preference is on socket cookie as selector.
	 */
	return get_prandom_u32();
#endif
}

#ifdef ENABLE_IPV4
__section("from-sock4")
int sock4_xlate(struct bpf_sock_addr *ctx)
{
	struct lb4_backend *backend;
	struct lb4_service_v2 *svc;
	struct lb4_key_v2 key = {
		.address	= ctx->user_ip4,
		.dport		= ctx_get_port(ctx),
	};
	struct lb4_service_v2 *slave_svc;

	svc = __lb4_lookup_service_v2(&key);
	if (svc) {
		key.slave = (sock_pick_rand(ctx) % svc->count) + 1;

		slave_svc = __lb4_lookup_slave_v2(&key);
		if (!slave_svc)
			return CONNECT_PROCEED;

		backend = __lb4_lookup_backend(slave_svc->backend_id);
		if (!backend)
			return CONNECT_PROCEED;

		ctx->user_ip4	= backend->address;
		ctx_set_port(ctx, backend->port);
	}

	return CONNECT_PROCEED;
}
#endif

#ifdef ENABLE_IPV6
static __always_inline void ctx_get_v6_address(struct bpf_sock_addr *ctx,
					       union v6addr *addr)
{
	addr->p1 = ctx->user_ip6[0];
	addr->p2 = ctx->user_ip6[1];
	addr->p3 = ctx->user_ip6[2];
	addr->p4 = ctx->user_ip6[3];
}

static __always_inline void ctx_set_v6_address(struct bpf_sock_addr *ctx,
					       union v6addr *addr)
{
	ctx->user_ip6[0] = addr->p1;
	ctx->user_ip6[1] = addr->p2;
	ctx->user_ip6[2] = addr->p3;
	ctx->user_ip6[3] = addr->p4;
}

__section("from-sock6")
int sock6_xlate(struct bpf_sock_addr *ctx)
{
	struct lb6_backend *backend;
	struct lb6_service_v2 *svc;
	struct lb6_key_v2 key = {
		.dport		= ctx_get_port(ctx),
	};
	struct lb6_service_v2 *slave_svc;

	ctx_get_v6_address(ctx, &key.address);

	svc = __lb6_lookup_service_v2(&key);
	if (svc) {
		key.slave = (sock_pick_rand(ctx) % svc->count) + 1;

		slave_svc = __lb6_lookup_slave_v2(&key);
		if (!slave_svc)
			return CONNECT_PROCEED;

		backend = __lb6_lookup_backend(slave_svc->backend_id);
		if (!backend)
			return CONNECT_PROCEED;

		ctx_set_v6_address(ctx, &backend->address);
		ctx_set_port(ctx, backend->port);
	}

	return CONNECT_PROCEED;
}
#endif

BPF_LICENSE("GPL");
