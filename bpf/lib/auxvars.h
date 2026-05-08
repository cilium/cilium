/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/compiler.h>
#include <bpf/helpers.h>

#define DEFINE_AUX(typ, name) \
	__section(".data.aux") typ __aux_##name;

volatile const __section(".rodata.aux") __u64 _aux_stride;
volatile const __section(".rodata.aux") __u64 _aux_max_off;

#define AUX(name) ({ \
	__u32 cpuid = get_smp_processor_id(); \
	void *aux_addr = (void *)&__aux_##name; \
	__u64 offset = (_aux_stride * cpuid); \
	if (offset > _aux_max_off) \
		offset = _aux_max_off; \
	aux_addr += offset; \
	(__typeof__(__aux_##name) *)(aux_addr); \
})
