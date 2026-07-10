/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/api.h>

#ifdef PREALLOCATE_MAPS
#define CONDITIONAL_PREALLOC 0
#else
#define CONDITIONAL_PREALLOC BPF_F_NO_PREALLOC
#endif

#ifdef NO_COMMON_MEM_MAPS
#define LRU_MEM_FLAVOR BPF_F_NO_COMMON_LRU
#else
#define LRU_MEM_FLAVOR 0
#endif

/* BPF_F_RDONLY_PROG makes maps read-only from BPF programs (but writable from
 * user-space). This prevents accidental updates from the datapath for maps that
 * should only be managed by the agent.
 * In BPF tests, we need to populate these maps from BPF programs, so we
 * conditionally disable the flag when BPF_TEST is defined.
 */
#ifdef BPF_TEST
#define BPF_F_RDONLY_PROG_COND 0
#else
#define BPF_F_RDONLY_PROG_COND BPF_F_RDONLY_PROG
#endif
