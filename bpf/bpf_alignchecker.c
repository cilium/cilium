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

#ifndef barrier_data
#define barrier_data(ptr) __asm__ __volatile__("": :"r"(ptr) :"memory")
#endif

int main() {
    struct ipv4_ct_tuple s0 = {};
    barrier_data(&s0);
    struct ipv6_ct_tuple s1 = {};
    barrier_data(&s1);
    struct ct_entry s2 = {};
    barrier_data(&s2);
    struct ipcache_key s3 = {};
    barrier_data(&s3);
    struct remote_endpoint_info s4 = {};
    barrier_data(&s4);
    struct lb4_key s5 = {};
    barrier_data(&s5);
    struct lb4_service s6 = {};
    barrier_data(&s6);
    struct lb6_key s7 = {};
    barrier_data(&s7);
    struct lb6_service s9 = {};
    barrier_data(&s9);
    struct endpoint_key s10 = {};
    barrier_data(&s10);
    struct endpoint_info s11 = {};
    barrier_data(&s11);
    struct metrics_key s12 = {};
    barrier_data(&s12);
    struct metrics_value s13 = {};
    barrier_data(&s13);
    struct proxy4_tbl_key s14 = {};
    barrier_data(&s14);
    struct proxy4_tbl_value s15 = {};
    barrier_data(&s15);
    struct proxy6_tbl_key s16 = {};
    barrier_data(&s16);
    struct proxy6_tbl_value s17 = {};
    barrier_data(&s17);
    struct sock_key s18 = {};
    barrier_data(&s18);
    struct ep_config s19 = {};
    barrier_data(&s19);

    return 0;
}
