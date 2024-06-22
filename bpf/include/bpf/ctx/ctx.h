/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#ifndef __ctx_buff
# error "No __ctx_buff context defined. Please either include 'bpf/ctx/skb.h' or 'bpf/ctx/xdp.h'."
#endif
