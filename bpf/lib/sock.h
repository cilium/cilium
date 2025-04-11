/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

static __always_inline __maybe_unused __sock_cookie
sock_local_cookie(struct bpf_sock_addr *ctx)
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

struct sock_term_filter {
	union {
		union v6addr addr6;
		struct {
			char pad[12];
			__be32 addr4;
		};
	} address __packed;
	__be16 port;
	__u8 address_family;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct sock_term_filter);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_sock_term_filter __section_maps_btf;

#ifdef ENABLE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_revnat_tuple);
	__type(value, struct ipv4_revnat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB4_REVERSE_NAT_SK_MAP_SIZE);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_lb4_reverse_sk __section_maps_btf;
#endif

#ifdef ENABLE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_revnat_tuple);
	__type(value, struct ipv6_revnat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB6_REVERSE_NAT_SK_MAP_SIZE);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_lb6_reverse_sk __section_maps_btf;
#endif
