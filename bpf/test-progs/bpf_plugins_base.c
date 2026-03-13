// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include "bpf_plugins.h"

int a_seq;
int a_ret;

__section_entry
int program_a(struct __ctx_buff *ctx __maybe_unused)
{
	a_seq = inc();
	return a_ret;
}

int b_seq;
int b_ret;

__section_entry
int program_b(struct __ctx_buff *ctx __maybe_unused)
{
	b_seq = inc();
	return b_ret;
}

BPF_LICENSE("Dual BSD/GPL");
