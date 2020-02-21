/*
 *  Copyright (C) 2018-2019 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* Ensure declaration of notification event types */
#define DEBUG
#define TRACE_NOTIFY
#define DROP_NOTIFY

#include "node_config.h"
#include "lib/conntrack.h"
#include "lib/dbg.h"
#include "lib/drop.h"
#define SKIP_UNDEF_LPM_LOOKUP_FN
#include "lib/lb.h"
#include "lib/maps.h"
#include "lib/nat.h"
#include "lib/trace.h"
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
    DECLARE_STRUCT(debug_msg, iter);
    DECLARE_STRUCT(debug_capture_msg, iter);
    DECLARE_STRUCT(ipv4_revnat_tuple, iter);
    DECLARE_STRUCT(ipv4_revnat_entry, iter);
    DECLARE_STRUCT(ipv6_revnat_tuple, iter);
    DECLARE_STRUCT(ipv6_revnat_entry, iter);

    return 0;
}
