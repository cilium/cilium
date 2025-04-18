/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

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
	__uint(max_entries, 1);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_sock_term_filter __section_maps_btf;

