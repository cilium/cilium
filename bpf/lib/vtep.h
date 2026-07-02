/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <bpf/section.h>
#include <bpf/loader.h>
#include <lib/static_data.h>

/* vtep_key uses the LPM trie format: prefixlen (in bits) followed by the
 * IPv4 address. When inserting, set prefixlen to the CIDR prefix length
 * (e.g. 24 for /24). When looking up from the datapath, set prefixlen=32
 * to match the full destination IP against all prefixes in the trie.
 */
struct vtep_key {
	struct bpf_lpm_trie_key lpm_key; /* prefixlen in bits */
	__u32 vtep_ip;
};

struct vtep_value {
	__u64 vtep_mac;
	__u32 tunnel_endpoint;
};

#ifdef ENABLE_VTEP
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct vtep_key);
	__type(value, struct vtep_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, VTEP_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_vtep_map __section_maps_btf;
#endif /* ENABLE_VTEP */
