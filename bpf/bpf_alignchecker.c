// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2020 Authors of Cilium */

/* Ensure declaration of notification event types */
#define DEBUG
#define TRACE_NOTIFY
#define DROP_NOTIFY
#define POLICY_VERDICT_NOTIFY

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include "node_config.h"
#include "lib/conntrack.h"
#include "lib/dbg.h"
#include "lib/drop.h"
#define SKIP_UNDEF_LPM_LOOKUP_FN
#include "lib/maps.h"
#include "lib/nat.h"
#include "lib/trace.h"
#include "lib/policy_log.h"
#include "sockops/bpf_sockops.h"

// DECLARE_STRUCT declares a unique usage of the struct 'x' on the stack.
//
// To prevent compiler from optimizing away the var, we pass a reference
// to the var to a BPF helper function which accepts a reference as
// an argument.
#define DECLARE_STRUCT(x, iter)			\
{						\
	struct x s ## iter = {};		\
	trace_printk("%p", 1, &s ## iter);	\
	iter++;					\
}

// This function is a placeholder for C struct definitions shared with Go, and
// it's never being executed.
int main() {
    int iter = 0;

    DECLARE_STRUCT(ipv4_ct_tuple, iter);
    DECLARE_STRUCT(ipv6_ct_tuple, iter);
    DECLARE_STRUCT(ct_entry, iter);
    DECLARE_STRUCT(ipcache_key, iter);
    DECLARE_STRUCT(remote_endpoint_info, iter);
    DECLARE_STRUCT(lb4_key, iter);
    DECLARE_STRUCT(lb4_service, iter);
    DECLARE_STRUCT(lb4_backend, iter);
    DECLARE_STRUCT(lb6_key, iter);
    DECLARE_STRUCT(lb6_service, iter);
    DECLARE_STRUCT(lb6_backend, iter);
    DECLARE_STRUCT(endpoint_key, iter);
    DECLARE_STRUCT(endpoint_info, iter);
    DECLARE_STRUCT(metrics_key, iter);
    DECLARE_STRUCT(metrics_value, iter);
    DECLARE_STRUCT(sock_key, iter);
    DECLARE_STRUCT(policy_key, iter);
    DECLARE_STRUCT(policy_entry, iter);
    DECLARE_STRUCT(ipv4_nat_entry, iter);
    DECLARE_STRUCT(ipv6_nat_entry, iter);
    DECLARE_STRUCT(trace_notify, iter);
    DECLARE_STRUCT(drop_notify, iter);
    DECLARE_STRUCT(policy_verdict_notify, iter);
    DECLARE_STRUCT(debug_msg, iter);
    DECLARE_STRUCT(debug_capture_msg, iter);
    DECLARE_STRUCT(ipv4_revnat_tuple, iter);
    DECLARE_STRUCT(ipv4_revnat_entry, iter);
    DECLARE_STRUCT(ipv6_revnat_tuple, iter);
    DECLARE_STRUCT(ipv6_revnat_entry, iter);

    return 0;
}
