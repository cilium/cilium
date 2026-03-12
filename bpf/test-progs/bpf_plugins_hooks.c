// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include "bpf_plugins.h"

int before_program_a_seq;
int before_program_a_ret;

__section("freplace/before_program_a")
int before_program_a(struct __ctx_buff *ctx __maybe_unused)
{
	before_program_a_seq = inc();
	return before_program_a_ret;
}

int after_program_a_seq;
int after_program_a_ret_param;
int after_program_a_ret;

__section("freplace/after_program_a")
int after_program_a(struct __ctx_buff *ctx __maybe_unused, int ret)
{
	after_program_a_seq = inc();
	after_program_a_ret_param = ret;
	return after_program_a_ret;
}

int before_program_b_seq;
int before_program_b_ret;

__section("freplace/before_program_b")
int before_program_b(struct __ctx_buff *ctx __maybe_unused)
{
	before_program_b_seq = inc();
	return before_program_b_ret;
}

int after_program_b_seq;
int after_program_b_ret_param;
int after_program_b_ret;

__section("freplace/after_program_b")
int after_program_b(struct __ctx_buff *ctx __maybe_unused, int ret)
{
	after_program_b_seq = inc();
	after_program_b_ret_param = ret;
	return after_program_b_ret;
}

BPF_LICENSE("Dual BSD/GPL");
