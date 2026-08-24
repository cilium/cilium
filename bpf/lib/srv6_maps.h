/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>

#include "lib/ipv6_core.h"

struct srv6_vrf_key4 {
	struct bpf_lpm_trie_key lpm;
	__u32 src_ip;
	__u32 dst_cidr;
};

struct srv6_vrf_key6 {
	struct bpf_lpm_trie_key lpm;
	union v6addr src_ip;
	union v6addr dst_cidr;
};

struct srv6_policy_key4 {
	struct bpf_lpm_trie_key lpm;
	__u32 vrf_id;
	__u32 dst_cidr;
};

struct srv6_policy_key6 {
	struct bpf_lpm_trie_key lpm;
	__u32 vrf_id;
	union v6addr dst_cidr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct srv6_vrf_key6);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SRV6_VRF_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_srv6_vrf_v6 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct srv6_policy_key6);
	__type(value, union v6addr);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SRV6_POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_srv6_policy_v6 __section_maps_btf;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, union v6addr); /* SID */
    __type(value, __u32);      /* VRF ID */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, SRV6_SID_MAP_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_srv6_sid __section_maps_btf;

struct srv6_srh {
	struct ipv6_rt_hdr rthdr;
	__u8 first_segment;
	__u8 flags;
	__u16 reserved;
	struct in6_addr segments[0];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct srv6_vrf_key4);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SRV6_VRF_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_srv6_vrf_v4 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct srv6_policy_key4);
	__type(value, union v6addr);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SRV6_POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_srv6_policy_v4 __section_maps_btf;
