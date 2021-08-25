/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// Header of functions to be mocked in lb.h.

#define __BPF_BUILTINS__
#include <bpf/ctx/skb.h>
#include "lib/common.h"
#include <linux/ip.h>
#include "lib/csum.h"

int mock_lb4_extract_key(struct __ctx_buff *ctx, struct iphdr *ip4, int l4_off, struct lb4_key *key, struct csum_offset *csum_off, int dir);

struct lb4_service *mock_lb4_lookup_service(struct lb4_key *key, const bool scope_switch);

int mock_lb4_local(const void *map, struct __ctx_buff *ctx, int l3_off, int l4_off, struct csum_offset *csum_off, struct lb4_key *key, struct ipv4_ct_tuple *tuple, const struct lb4_service *svc, struct ct_state *state, __be32 saddr, bool has_l4_header, const bool skip_l3_xlate);

int mock_lb4_rev_nat(struct __ctx_buff *ctx, int l3_off, int l4_off, struct csum_offset *csum_off, struct ct_state *ct_state, struct ipv4_ct_tuple *tuple, int flags, bool has_l4_header);
