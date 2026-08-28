/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/compiler.h>
#include <bpf/helpers.h>

#define DEFINE_AUX(typ, name) \
	__section(".data.aux") typ __aux_##name

volatile const __section(".rodata.aux") __u64 _aux_cpu_mask;
volatile const __section(".rodata.aux") __u64 _aux_stride_shift;

/*
 * The AUX[_REUSE] macros are used to access per-CPU auxiliary variables. It calculates
 * the address of the variable for the current CPU by adding an offset based on
 * the CPU ID and a stride shift value.
 *
 * Once the minimum kernel version supported is v6.6, let's replace this and
 * switch back to the previous implementation to avoid the memory overhead.
 * (see https://github.com/cilium/cilium/issues/48301)
 */

/* AUX_REUSE() returns a pointer to an auxvar of the given name, without zeroing it out.
 * Use this for transferring data between functions or tail calls.
 */
#define AUX_REUSE(name) \
	((__typeof__(__aux_##name) *)((void *)&__aux_##name + \
	 ((get_smp_processor_id() & _aux_cpu_mask) << _aux_stride_shift)))

/* AUX() returns a pointer to an auxvar of the given name, and zeroes it out.
 * Use this for additional non-stack scratch space.
 */
#define AUX(name) ({ \
	__typeof__(__aux_##name) *ptr = AUX_REUSE(name); \
	__bpf_memzero(ptr, sizeof(*ptr)); \
	ptr; \
})
