/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_LOADER__
#define __BPF_LOADER__

#include <linux/types.h>

#define __uint(name, val) int(*(name))[val]
#define __type(name, val) typeof(val) *(name)
#define __array(name, val) typeof(val) *(name)[]

#define LIBBPF_PIN_BY_NAME 1
/* Pin per-endpoint map to `/sys/fs/bpf/cilium/endpoints/<endpoint>/<map>` and
	 replace the pin after endpoint has successfully attached. Never repopulates
	 existing map, always removes existing pin before pinning. */
#define CILIUM_PIN_PER_EP_REPLACE 1<<4

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

#endif /* __BPF_LOADER__ */
