/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BPF_LOADER__
#define __BPF_LOADER__

#include <linux/types.h>

#define PIN_NONE		0
#define PIN_OBJECT_NS		1
#define PIN_GLOBAL_NS		2

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
	__u32 inner_id;
	__u32 inner_idx;
};

#define NO_PREPOPULATE		-1

#endif /* __BPF_LOADER__ */
