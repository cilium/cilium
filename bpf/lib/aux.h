/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "bpf/helpers.h"
#include "conntrack_types.h"
#include "trace_types.h"
#include "ratelimit.h"
#include "nat_types.h"
#include "policy_types.h"

/* Auxiliary data, used to store variables outside of the stack */
struct aux_data {
        struct ct_entry ct_entry;
        struct trace_notify msg;
        struct policy_verdict_notify policy_msg;
        struct ratelimit_settings ratelimit_settings;
        struct ipv6_ct_tuple rtuple;
        struct ipv6_ct_tuple tuple;
        struct ipv6_ct_tuple icmp_tuple;
        struct ipv6_nat_entry rstate;
	struct ipv6hdr ip6;
        struct ct_buffer4 ct_buffer4;
        struct ct_buffer6 ct_buffer6;
        struct bpf_fib_lookup_padded fib_params;
};

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, __u32);
        __type(value, struct aux_data);
        __uint(max_entries, 1);
} cilium_aux_data __section_maps_btf;

struct aux_data *get_aux_data(void)
{
        __u32 key = 0;
        return map_lookup_elem(&cilium_aux_data, &key);
}
