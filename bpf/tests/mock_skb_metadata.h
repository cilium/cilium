/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef ____BPF_TEST_MOCK_SKB_METADATA____
#define ____BPF_TEST_MOCK_SKB_METADATA____

#include <bpf/compiler.h>
#include <bpf/helpers.h>
#include <bpf/loader.h>
#include <bpf/section.h>
#include <linux/bpf.h>
#include <linux/types.h>

/*
 * You can mock out ctx_store_meta and ctx_load_meta for skb
 * by including this file. The user space program automatically
 * clears the values after the single test.
 */

struct mock_skb_meta {
	__u32 cb[5];
	__u32 _pad0;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct mock_skb_meta));
	__uint(max_entries, 1);
} mock_skb_meta_map __section_maps_btf;

static __always_inline __maybe_unused void
mock_skb_store_meta(struct __sk_buff *ctx __maybe_unused, const __u32 off,
		    __u32 data)
{
	__u32 idx = 0;
	struct mock_skb_meta *meta;

	meta = map_lookup_elem(&mock_skb_meta_map, &idx);
	if (!meta)
		return;

	meta->cb[off] = data;
}

static __always_inline __maybe_unused __u32
mock_skb_load_meta(const struct __sk_buff *ctx __maybe_unused, const __u32 off)
{
	__u32 idx = 0;
	struct mock_skb_meta *meta;

	meta = map_lookup_elem(&mock_skb_meta_map, &idx);
	if (!meta)
		return 0;

	return meta->cb[off];
}

#define ctx_store_meta mock_skb_store_meta
#define ctx_load_meta mock_skb_load_meta

#endif /* ____BPF_TEST_MOCK_SKB_METADATA____ */
