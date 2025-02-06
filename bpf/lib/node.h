/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <bpf/section.h>
#include <bpf/loader.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct node_key);
	__type(value, struct node_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, NODE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_node_map_v2 __section_maps_btf;
