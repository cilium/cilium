/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <bpf/section.h>
#include <bpf/loader.h>

struct vtep_key {
	__u32 vtep_ip;
};

struct vtep_value {
	__u64 vtep_mac;
	__u32 tunnel_endpoint;
};

#ifdef ENABLE_VTEP
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct vtep_key);
	__type(value, struct vtep_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, VTEP_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} cilium_vtep_map __section_maps_btf;
#endif /* ENABLE_VTEP */
