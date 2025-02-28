// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>
#include <bpf/helpers.h>

#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
struct seq_file;
struct bpf_iter_meta {
	struct seq_file *seq;
	__u64 session_id;
	__u64 seq_num;
};

struct bpf_map {
	__u32 id;
	char name[16];
	__u32 max_entries;
};

struct bpf_iter__bpf_map {
	struct bpf_iter_meta *meta;
	struct bpf_map *map;
};

#pragma clang attribute pop

__s64 bpf_map_sum_elem_count(struct bpf_map *map) __ksym;

__section("iter/bpf_map")
int dump_bpf_map(struct bpf_iter__bpf_map *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct bpf_map *map = ctx->map;

	if (!map)
		return 0;

	SEQ_PRINTF(seq, "%u %s %d %lld\n",
		       map->id, map->name, map->max_entries,
		       bpf_map_sum_elem_count(map));

	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
