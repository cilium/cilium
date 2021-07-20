// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019-2020 Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#define SYS_REJECT	0

struct bpf_elf_map __section_maps cilium_netns_cookie = {
	.type       = BPF_MAP_TYPE_ARRAY,
	.size_key   = sizeof(__u32),
	.size_value = sizeof(__net_cookie),
	.pinning    = PIN_GLOBAL_NS,
	.max_elem   = 1,
};

__section("sock_aux_get_netns_cookie")
int stub_get_netns_cookie(struct bpf_sock_addr *ctx __maybe_unused)
{
#if defined(SOCKET_MAGIC_COOKIE)    && \
    defined(BPF_HAVE_NETNS_COOKIE)  && \
    defined(BPF_HAVE_SOCKET_COOKIE)
	__u32 index = 0;
	__net_cookie netns_cookie;
	__sock_cookie sock_cookie = get_socket_cookie(ctx);

	if (sock_cookie == SOCKET_MAGIC_COOKIE) {
		netns_cookie = get_netns_cookie(ctx);
		map_update_elem(&cilium_netns_cookie, &index, &netns_cookie, 0);
	}
#endif
	return SYS_REJECT;
}

BPF_LICENSE("GPL");
