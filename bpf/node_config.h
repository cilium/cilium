/*
 *  Copyright (C) 2016-2019 Authors of Cilium
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
#include "lib/utils.h"

DEFINE_IPV6(ROUTER_IP, 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0);
#define ENCAP_IFINDEX 1
#define HOST_IFINDEX 1
#define CILIUM_IFINDEX 1
DEFINE_IPV6(HOST_IP, 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0xa, 0x0, 0x2, 0xf, 0xff, 0xff);
#define HOST_ID 1
#define WORLD_ID 2
#define UNMANAGED_ID 3
#define HEALTH_ID 4
#define INIT_ID 5
#define HOST_IFINDEX_MAC { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 } }
#define NAT46_PREFIX { .addr = { 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define ENABLE_MASQUERADE 1
#define BPF_PKT_DIR 1

#ifdef ENABLE_MASQUERADE
#define SNAT_MAPPING_MIN_PORT 1024
#define SNAT_MAPPING_MAX_PORT 65535
#define SNAT_COLLISION_RETRIES 16
#endif

#ifdef ENABLE_IPV4
#define IPV4_MASK 0xffff
#define IPV4_GATEWAY 0xfffff50a
#define IPV4_LOOPBACK 0x1ffff50a
#ifdef ENABLE_MASQUERADE
#define SNAT_IPV4_EXTERNAL IPV4_GATEWAY
#define SNAT_MAPPING_IPV4 cilium_snat_v4_external
#define SNAT_MAPPING_IPV4_SIZE 524288
#endif /* ENABLE_MASQUERADE */
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
#ifdef ENABLE_MASQUERADE
DEFINE_IPV6(SNAT_IPV6_EXTERNAL, 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0);
#define SNAT_MAPPING_IPV6 cilium_snat_v6_external
#define SNAT_MAPPING_IPV6_SIZE 524288
#endif /* ENABLE_MASQUERADE */
#endif /* ENABLE_IPV6 */

#define ENCAP_GENEVE 1
#define ENDPOINTS_MAP test_cilium_lxc
#define EVENTS_MAP test_cilium_events
#define METRICS_MAP test_cilium_metrics
#define POLICY_CALL_MAP test_cilium_policy
#define SOCK_OPS_MAP test_sock_ops_map
#define IPCACHE_MAP test_cilium_ipcache
#define PROXY4_MAP test_cilium_proxy4
#define PROXY6_MAP test_cilium_proxy6
#define TUNNEL_MAP test_cilium_tunnel_map
#define EP_POLICY_MAP test_cilium_ep_to_policy
#define LB6_REVERSE_NAT_MAP test_cilium_lb6_reverse_nat
#define LB6_SERVICES_MAP test_cilium_lb6_services
#define LB6_SERVICES_MAP_V2 test_cilium_lb6_services_v2
#define LB6_RR_SEQ_MAP test_cilium_lb6_rr_seq
#define LB6_RR_SEQ_MAP_V2 test_cilium_lb6_rr_seq_v2
#define LB6_BACKEND_MAP test_cilium_lb6_backends
#define LB4_REVERSE_NAT_MAP test_cilium_lb4_reverse_nat
#define LB4_SERVICES_MAP test_cilium_lb4_services
#define LB4_SERVICES_MAP_V2 test_cilium_lb4_services_v2
#define LB4_RR_SEQ_MAP test_cilium_lb4_rr_seq
#define LB4_RR_SEQ_MAP_V2 test_cilium_lb4_rr_seq_v2
#define LB4_BACKEND_MAP test_cilium_lb4_backends
#define ENABLE_ARP_RESPONDER
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
#define MONITOR_AGGREGATION 5
#define MTU 1500
#define ENABLE_IPSEC

#ifdef ENABLE_MASQUERADE
#define CT_MAP_TCP6 test_cilium_ct_tcp6_65535
#define CT_MAP_ANY6 test_cilium_ct_any6_65535
#define CT_MAP_TCP4 test_cilium_ct_tcp4_65535
#define CT_MAP_ANY4 test_cilium_ct_any4_65535
#define CT_MAP_SIZE_TCP 4096
#define CT_MAP_SIZE_ANY 4096
#define CONNTRACK
#define CONNTRACK_ACCOUNTING
#endif
