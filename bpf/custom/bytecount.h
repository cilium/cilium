// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2021 Authors of Cilium */

struct bpf_elf_map __section_maps bytecount_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u64),
	.max_elem	= 1024,
};

static __always_inline
void custom_prog(const struct __ctx_buff *ctx, __u32 identity)
{
	__u64 len, *bytecount;

	len = ctx_full_len(ctx);

	bytecount = map_lookup_elem(&bytecount_map, &identity);
	if (bytecount)
		__sync_fetch_and_add(bytecount, len);
	else
		/* No entry for endpoint in hashmap, attempt to create one */
		map_update_elem(&bytecount_map, &identity, &len, BPF_ANY);
}
