/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <bpf/section.h>
#include <bpf/loader.h>

struct l2_responder_v4_key {
	__u32 ip4;
	__u32 ifindex;
};

struct l2_responder_v4_stats {
	__u64 responses_sent;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct l2_responder_v4_key);
	__type(value, struct l2_responder_v4_stats);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, L2_RESPONDER_MAP4_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_l2_responder_v4 __section_maps_btf;
