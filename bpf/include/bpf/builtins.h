/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BPF_BUILTINS__
#define __BPF_BUILTINS__

#include "compiler.h"

#ifndef lock_xadd
# define lock_xadd(P, V)	((void) __sync_fetch_and_add((P), (V)))
#endif

#ifndef memset
# define memset(S, C, N)	__builtin_memset((S), (C), (N))
#endif

#ifndef memcpy
# define memcpy(D, S, N)	__builtin_memcpy((D), (S), (N))
#endif

#ifndef memmove
# define memmove(D, S, N)	__builtin_memmove((D), (S), (N))
#endif

/* NOTE: https://llvm.org/bugs/show_bug.cgi?id=26218 */
#ifndef memcmp
# define memcmp(A, B, N)	__builtin_memcmp((A), (B), (N))
#endif

#endif /* __BPF_BUILTINS__ */
