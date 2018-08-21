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
 *
 *
 *                     **** WARNING ****
 * This is just a dummy header with dummy values to allow for test
 * compilation without the full code generation engine backend.
 *
 *
 *
 */

#define ROUTER_IP 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0
#define ENCAP_IFINDEX 1
#define HOST_IFINDEX 1
#define HOST_IP 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x2, 0xf, 0xff, 0xff
#define HOST_ID 1
#define WORLD_ID 2
#define CLUSTER_ID 3
#define HOST_IFINDEX_MAC { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 } }
#define NAT46_PREFIX { .addr = { 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define IPV4_MASK 0xffff
#define IPV4_CLUSTER_MASK 0xff0000
#define IPV4_CLUSTER_RANGE 0x100000
#define IPV4_GATEWAY 0xfffff50a
#define IPV4_LOOPBACK 0x1ffff50a
#define ENCAP_GENEVE 1
#define CALLS_MAP cilium_calls_111
#define SECLABEL 2
#define SECLABEL_NB 0xfffff
#define ENABLE_ARP_RESPONDER
#define NODE_MAC { .addr = { 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde } }
#define ENABLE_IPV4
#define LB_RR_MAX_SEQ 31
#define TUNNEL_ENDPOINT_MAP_SIZE 65536
#define ENDPOINTS_MAP_SIZE 65536
#define METRICS_MAP_SIZE 65536
#define CILIUM_NET_MAC  { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x57 } }
#define LB_REDIRECT 1
#define LB_DST_MAC { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x58 } }
#define CILIUM_LB_MAP_MAX_ENTRIES	65536
#define PROXY_MAP_SIZE 524288
#define POLICY_MAP_SIZE 16384
#define IPCACHE_MAP_SIZE 512000
#define POLICY_PROG_MAP_SIZE ENDPOINTS_MAP_SIZE
#ifndef SKIP_DEBUG
#define LB_DEBUG
#endif
