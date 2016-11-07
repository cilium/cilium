/*
 *  Copyright (C) 2016 Authors of Cilium
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

#define NODE_ID 0x10001
#define ROUTER_IP { 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0 }
#define ENCAP_IFINDEX 1
#define HOST_IFINDEX 1
#define HOST_IP { .addr = { 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x2, 0xf, 0xff, 0xff } }
#define HOST_ID 1
#define WORLD_ID 2
#define HOST_IFINDEX_MAC { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 } }
#define NAT46_PREFIX { .addr = { 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define IPV4_RANGE 0xf50a
#define IPV4_MASK 0xffff
#define IPV4_CLUSTER_MASK 0xff0000
#define IPV4_CLUSTER_RANGE 0x100000
#define IPV4_GATEWAY 0xfffff50a
#define ENCAP_GENEVE 1
#define SECLABEL 2
#define SECLABEL_NB 0xfffff
#define ENABLE_ARP_RESPONDER
#define NODE_MAC { .addr = { 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde } }
