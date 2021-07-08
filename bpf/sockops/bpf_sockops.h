/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2020 Authors of Cilium */

#include "sockops_config.h"

/* Structure representing an L7 sock */
struct sock_key {
	union {
		struct {
			__u32		sip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	sip6;
	};
	union {
		struct {
			__u32		dip4;
			__u32		pad4;
			__u32		pad5;
			__u32		pad6;
		};
		union v6addr	dip6;
	};
	__u8 family;
	__u8 protocol;
	__u16 pad8;
	__u32 sport;
	__u32 dport;
} __packed;

struct bpf_elf_map __section_maps SOCK_OPS_MAP = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.size_key       = sizeof(struct sock_key),
	.size_value     = sizeof(int),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = SOCKOPS_MAP_SIZE,
};
