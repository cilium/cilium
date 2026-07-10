/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#if __ctx_is == __ctx_skb
# include "lib/overloadable_skb.h"
#else
# include "lib/overloadable_xdp.h"
#endif
