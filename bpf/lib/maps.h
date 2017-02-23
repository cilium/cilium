/*
 *  Copyright (C) 2016-2017 Authors of Cilium
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
#ifndef __LIB_MAPS_H_
#define __LIB_MAPS_H_

#include "common.h"

#define CILIUM_MAP_LXC		0
#define CILIUM_MAP_POLICY	1
#define CILIUM_MAP_CALLS	2
#define CILIUM_MAP_RES_POLICY	3

__BPF_MAP(cilium_lxc, BPF_MAP_TYPE_HASH, CILIUM_MAP_LXC, sizeof(__u32), sizeof(struct lxc_info), PIN_GLOBAL_NS, 1024);

/* Global map to jump into policy enforcement of receiving endpoint */
BPF_PROG_ARRAY(cilium_policy, CILIUM_MAP_POLICY, PIN_GLOBAL_NS, POLICY_MAP_SIZE);
BPF_PROG_ARRAY(cilium_reserved_policy, CILIUM_MAP_RES_POLICY, PIN_GLOBAL_NS, RESERVED_POLICY_SIZE);

/* Private map for internal tail calls */
BPF_PROG_ARRAY(cilium_calls, CILIUM_MAP_CALLS, PIN_OBJECT_NS, CILIUM_CALL_SIZE);

#endif
