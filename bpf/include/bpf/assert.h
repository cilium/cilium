/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#if defined(BPF_TEST) || defined(BPF_CI)
# define load_time_unreachable() asm volatile("r10 = 0xbadc0f19 ll")
#else
# define load_time_unreachable() ((void)0)
#endif
