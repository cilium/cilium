// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include "lib/exits.h"

__section_entry
int cil_exit(struct __ctx_buff *ctx __maybe_unused)
{
	return get_cilium_return();
}

BPF_LICENSE("Dual BSD/GPL");
