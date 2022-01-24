/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2022 Authors of Cilium */

#ifndef __LIB_LOOP_H_
#define __LIB_LOOP_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#ifdef HAVE_BOUNDED_LOOPS
# define __bounded_loop		/* no unroll */
#else /* !HAVE_BOUNDED_LOOPS */
# define __bounded_loop		_Pragma("unroll")
#endif

#endif /* __LIB_LOOP_H_ */
