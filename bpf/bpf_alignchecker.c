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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/byteorder.h>
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/resource.h>
#include "node_config.h"
#include "lib/conntrack.h"
#include "lib/maps.h"
#include "sockops/bpf_sockops.h"

int main() {
    __attribute__((unused)) struct ipv4_ct_tuple s0;
    __attribute__((unused)) struct ipv6_ct_tuple s1;
    __attribute__((unused)) struct ct_entry s2;
    __attribute__((unused)) struct ipcache_key s3;
    __attribute__((unused)) struct remote_endpoint_info s4;
    __attribute__((unused)) struct lb4_key s5;
    __attribute__((unused)) struct lb4_service s6;
    __attribute__((unused)) struct lb6_key s7;
    __attribute__((unused)) struct lb6_service s9;
    __attribute__((unused)) struct endpoint_key s10;
    __attribute__((unused)) struct endpoint_info s11;
    __attribute__((unused)) struct metrics_key s12;
    __attribute__((unused)) struct metrics_value s13;
    __attribute__((unused)) struct proxy4_tbl_key s14;
    __attribute__((unused)) struct proxy4_tbl_value s15;
    __attribute__((unused)) struct proxy6_tbl_key s16;
    __attribute__((unused)) struct proxy6_tbl_value s17;
    __attribute__((unused)) struct sock_key s18;
    __attribute__((unused)) struct ep_config s19;

    return 0;
}
