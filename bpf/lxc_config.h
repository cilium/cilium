/*
 *  Copyright (C) 2016-2018 Authors of Cilium
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

#define LXC_IP 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1, 0x1, 0x65, 0x82, 0xbc
#define LXC_IPV4 0x10203040
#define LXC_ID 0x1010
#define LXC_ID_NB 0x1010
#define ENABLE_NAT46
#ifndef SECLABEL
#define SECLABEL 0xfffff
#define SECLABEL_NB 0xfffff
#endif
#define POLICY_MAP cilium_policy_foo
#define NODE_MAC { .addr = { 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde } }
#ifndef SKIP_DEBUG
#define DEBUG
#endif
#define DROP_NOTIFY
#define TRACE_NOTIFY
#define CT_MAP_TCP6 cilium_ct_tcp6_111
#define CT_MAP_ANY6 cilium_ct_any6_111
#define CT_MAP_TCP4 cilium_ct_tcp4_111
#define CT_MAP_ANY4 cilium_ct_any4_111
#define CT_MAP_SIZE_TCP 4096
#define CT_MAP_SIZE_ANY 4096
#define CALLS_MAP cilium_calls_111
#define LB_L3
#define LB_L4
#define CONNTRACK
#define CONNTRACK_ACCOUNTING
#define ENABLE_IPv4
#define CONFIG_MAP cilium_ep_config_111
#define EGRESS_MAP lxc_ipve_111

/* It appears that we can support around the below number of prefixes in an
 * unrolled loop for LPM CIDR handling in older kernels along with the rest of
 * the logic in the datapath, hence the defines below. This number was arrived
 * to by adjusting the number of prefixes and running:
 *
 *    $ make -C bpf && sudo test/bpf/verifier-test.sh
 *
 *  If you're from a future where all supported kernels include LPM map type,
 *  consider deprecating the hash-based CIDR lookup and removing the below.
 */
#define IPCACHE4_PREFIXES 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, \
4, 3, 2, 1
#define IPCACHE6_PREFIXES 4, 3, 2, 1
