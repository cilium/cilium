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
#include <stdio.h>
#include <linux/byteorder.h>
#include "node_config.h"
#include "lib/conntrack.h"
#include "lib/maps.h"
#include "sockops/bpf_sockops.h"

// This function is a placeholder for C struct definitions shared with Go, and
// it's never being executed.
int main() {
    struct ipv4_ct_tuple s0 = {};
    // To prevent compiler from optimizing away the var, we pass a reference
    // to the var to a BPF helper function which accepts a reference as
    // an argument.
    trace_printk("%p", 1, &s0);
    struct ipv6_ct_tuple s1 = {};
    trace_printk("%p", 1, &s1);
    struct ct_entry s2 = {};
    trace_printk("%p", 1, &s2);
    struct ipcache_key s3 = {};
    trace_printk("%p", 1, &s3);
    struct remote_endpoint_info s4 = {};
    trace_printk("%p", 1, &s4);
    struct lb4_key s5 = {};
    trace_printk("%p", 1, &s5);
    struct lb4_service s6 = {};
    trace_printk("%p", 1, &s6);
    struct lb6_key s7 = {};
    trace_printk("%p", 1, &s7);
    struct lb6_service s8 = {};
    trace_printk("%p", 1, &s8);
    struct endpoint_key s9 = {};
    trace_printk("%p", 1, &s9);
    struct endpoint_info s10 = {};
    trace_printk("%p", 1, &s10);
    struct metrics_key s11 = {};
    trace_printk("%p", 1, &s11);
    struct metrics_value s12 = {};
    trace_printk("%p", 1, &s12);
    struct proxy4_tbl_key s13 = {};
    trace_printk("%p", 1, &s13);
    struct proxy4_tbl_value s14 = {};
    trace_printk("%p", 1, &s14);
    struct proxy6_tbl_key s15 = {};
    trace_printk("%p", 1, &s15);
    struct proxy6_tbl_value s16 = {};
    trace_printk("%p", 1, &s16);
    struct sock_key s17 = {};
    trace_printk("%p", 1, &s17);
    struct ep_config s18 = {};
    trace_printk("%p", 1, &s18);

    return 0;
}
