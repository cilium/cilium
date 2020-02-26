/*
 *  Copyright (C) 2016-2020 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
