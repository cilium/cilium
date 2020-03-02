/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BPF_API__
#define __BPF_API__

#include <linux/types.h>
#include <linux/byteorder.h>
#include <linux/bpf.h>
#include <linux/if_packet.h>

#include "compiler.h"
#include "section.h"
#include "helpers.h"
#include "builtins.h"
#include "verifier.h"
#include "errno.h"

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
#ifdef SOCKMAP
	__u32 inner_id;
	__u32 inner_idx;
#endif
};

#endif /* __BPF_API__ */
