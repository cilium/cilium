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
