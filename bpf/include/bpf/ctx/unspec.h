/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __BPF_CTX_UNSPEC_H_
#define __BPF_CTX_UNSPEC_H_

/* We do not care which context we need in this case, but it must be
 * something compilable, thus we reuse skb ctx here.
 */

#ifdef __non_bpf_context
/* Do not include BPF feature header. */
# define __BPF_FEATURES_SKB__	1
#endif

#include "skb.h"

#endif /* __BPF_CTX_UNSPEC_H_ */
