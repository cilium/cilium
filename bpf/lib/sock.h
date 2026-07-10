/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "ipv6_core.h"
#include "map_defs.h"

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

struct ipv4_revnat_tuple {
	__sock_cookie cookie;
	__be32 address;
	__be16 port;
	__u16 pad;
};

struct ipv4_revnat_entry {
	__be32 address;
	__be16 port;
	__u16 rev_nat_index;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_revnat_tuple);
	__type(value, struct ipv4_revnat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB4_REVERSE_NAT_SK_MAP_SIZE);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_lb4_reverse_sk __section_maps_btf;

struct ipv6_revnat_tuple {
	__sock_cookie cookie;
	union v6addr address;
	__be16 port;
	__u16 pad;
};

struct ipv6_revnat_entry {
	union v6addr address;
	__be16 port;
	__u16 rev_nat_index;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_revnat_tuple);
	__type(value, struct ipv6_revnat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB6_REVERSE_NAT_SK_MAP_SIZE);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_lb6_reverse_sk __section_maps_btf;
