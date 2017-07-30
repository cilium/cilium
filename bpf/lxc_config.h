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
/*
 * This is just a dummy header with dummy values to allow for test
 * compilation without the full code generation engine backend.
 */

#define LXC_MAC { .addr = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } }
#define LXC_IP 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1, 0x1, 0x65, 0x82, 0xbc
#define LXC_IPV4 0x10203040
#define LXC_ID 0x1010
#define LXC_ID_NB 0x1010
#ifndef SECLABEL
#define SECLABEL 0xfffff
#define SECLABEL_NB 0xfffff
#endif
#define POLICY_MAP cilium_policy_foo
#define NODE_MAC { .addr = { 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde } }
#define GENEVE_OPTS { 0xff, 0xff, 0x1, 0x1, 0x0, 0x0, 0x1, 0x1e }
#define DROP_NOTIFY
#undef CT_MAP6
#define CT_MAP6 cilium_ct6_111
#undef CT_MAP4
#define CT_MAP4 cilium_ct4_111
#undef CT_MAP_SIZE
#define CT_MAP_SIZE 4096
#define CALLS_MAP cilium_calls_111
#define LB_L3
#define LB_L4
#define CONNTRACK
#define NR_CFG_L4_INGRESS 2
#define CFG_L4_INGRESS 0, 80, 8080, 0, 1, 80, 8080, 0, (), 0
#define NR_CFG_L4_EGRESS 1
#define CFG_L4_EGRESS 0, 80, 8080, 0, (), 0
