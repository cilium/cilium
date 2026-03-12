// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include "common.h"

__section("freplace")
int before(struct bpf_sock *ctx __maybe_unused)
{
	printk("before %s\n", attachment_context);

	return SYS_PROCEED;
}

__section("freplace")
int after(struct bpf_sock *ctx __maybe_unused, int ret)
{
	printk("after %s (ret=%d)\n", attachment_context, ret);

	return SYS_PROCEED;
}

BPF_LICENSE("Dual BSD/GPL");

