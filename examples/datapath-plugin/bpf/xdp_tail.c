// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include "common.h"

__section("xdp/tail")
int before(struct __ctx_buff *ctx __maybe_unused)
{
	printk("before %s\n", attachment_context);

	return TC_ACT_UNSPEC;
}

BPF_LICENSE("Dual BSD/GPL");
