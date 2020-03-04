/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium */

#ifndef __LIB_OVERLOADABLE_H_
#define __LIB_OVERLOADABLE_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#if __ctx_is == __ctx_skb
# include "lib/overloadable_skb.h"
#else
# include "lib/overloadable_xdp.h"
#endif

#endif /* __LIB_OVERLOADABLE_H_ */
