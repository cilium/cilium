/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "bpf/compiler.h"
#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, int);
	__uint(max_entries, 1);
} seq __section_maps_btf;

static int __maybe_unused inc(void)
{
	__u32 zero = 0;
	int *v;

	v = map_lookup_elem(&seq, &zero);
	if (!v)
		return 0;

	return ++(*v);
}

#define PROGRAM(SECTION, NAME, CTX_TYPE)        \
int program_##NAME##_seq;                       \
__section(SECTION)                              \
int program_##NAME(CTX_TYPE ctx __maybe_unused) \
{                                               \
	program_##NAME##_seq = inc();           \
	return 1;                               \
}

static int __maybe_unused clamp(int ret, int min, int max)
{
	if (ret < min)
		return min;
	if (ret > max)
		return max;

	return ret;
}

#define PRE(NAME, CTX_TYPE, MIN_RET, MAX_RET)          \
int before_program_##NAME##_seq;                       \
int before_program_##NAME##_ret;                       \
__section("freplace")                                  \
int before_program_##NAME(CTX_TYPE ctx __maybe_unused) \
{                                                      \
	before_program_##NAME##_seq = inc();           \
	return clamp(before_program_##NAME##_ret,      \
		     MIN_RET,                          \
		     MAX_RET);                         \
}

#define POST(NAME, CTX_TYPE, MIN_RET, MAX_RET)                 \
int after_program_##NAME##_seq;                                \
int after_program_##NAME##_ret_param;                          \
int after_program_##NAME##_ret;                                \
__section("freplace")                                          \
int after_program_##NAME(CTX_TYPE ctx __maybe_unused, int ret) \
{                                                              \
	after_program_##NAME##_seq = inc();                    \
	after_program_##NAME##_ret_param = ret;                \
	return clamp(after_program_##NAME##_ret,               \
		     MIN_RET,                                  \
		     MAX_RET);                                 \
}
