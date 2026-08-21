/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/compiler.h>
#include <bpf/helpers.h>

#define DEFINE_AUX(typ, name) \
	__section(".data.aux") typ __aux_##name;

volatile const __section(".rodata.aux") __u64 _aux_cpu_mask;
volatile const __section(".rodata.aux") __u64 _aux_stride_shift;

#define AUX(name) \
	((__typeof__(__aux_##name) *)((void *)&__aux_##name + \
	 ((get_smp_processor_id() & _aux_cpu_mask) << _aux_stride_shift)))
