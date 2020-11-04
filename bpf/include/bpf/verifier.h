/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BPF_VERIFIER__
#define __BPF_VERIFIER__

#include "csum.h"

/* relax_verifier is a dummy helper call to introduce a pruning checkpoint
 * to help relax the verifier to avoid reaching complexity limits on older
 * kernels.
 */
static __always_inline void relax_verifier(void)
{
#ifdef NEEDS_RELAX_VERIFIER
       int foo = 0;

       csum_diff(0, 0, &foo, 1, 0);
#endif
}

#endif /* __BPF_VERIFIER__ */
