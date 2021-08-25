/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// Header of functions to be mocked in l3.h.

#define __BPF_BUILTINS__
#include <bpf/ctx/skb.h>
#include "lib/common.h"
#include <linux/ip.h>

int mock_ipv4_local_delivery(struct __ctx_buff *ctx, int l3_off, __u32 seclabel, struct iphdr *ip4, const struct endpoint_info *ep, __u8 direction, bool from_host);

int mock_ipv4_l3(struct __ctx_buff *ctx, int l3_off, const __u8 *smac, const __u8 *dmac, struct iphdr *ip4);
