/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

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

DEFINE_MAC(NODE_MAC, 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde);
#define NODE_MAC fetch_mac(NODE_MAC)

DEFINE_IPV6(ROUTER_IP, 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0);
#define HOST_IFINDEX 1
#define CILIUM_IFINDEX 1
#define NATIVE_DEV_MAC_BY_IFINDEX(_) { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 } }
DEFINE_IPV6(HOST_IP, 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0xa, 0x0, 0x2, 0xf, 0xff, 0xff);
#define HOST_ID 1
#define WORLD_ID 2
#define UNMANAGED_ID 3
#define HEALTH_ID 4
#define INIT_ID 5
#define LOCAL_NODE_ID 6
#define REMOTE_NODE_ID 6
#define HOST_IFINDEX_MAC { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 } }
#define NAT46_PREFIX { .addr = { 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define NODEPORT_PORT_MIN 30000
#define NODEPORT_PORT_MAX 32767
#define NODEPORT_PORT_MIN_NAT (NODEPORT_PORT_MAX + 1)
#define NODEPORT_PORT_MAX_NAT 43835

#define CT_CONNECTION_LIFETIME_TCP	21600
#define CT_CONNECTION_LIFETIME_NONTCP	60
#define CT_SERVICE_LIFETIME_TCP		21600
#define CT_SERVICE_LIFETIME_NONTCP	60
#define CT_SYN_TIMEOUT			60
#define CT_CLOSE_TIMEOUT		10
#define CT_REPORT_INTERVAL		5
#ifndef CT_REPORT_FLAGS
# define CT_REPORT_FLAGS		0xff
#endif

#define KERNEL_HZ 250   /* warp: 0 jiffies */

#define ENABLE_IDENTITY_MARK 1

#define HASH_INIT4_SEED 0xcafe
#define HASH_INIT6_SEED 0xeb9f

#ifdef ENABLE_IPV4
#define IPV4_MASK 0xffff
#define IPV4_GATEWAY 0xfffff50a
#define IPV4_LOOPBACK 0x1ffff50a
#ifdef ENABLE_NODEPORT
#define SNAT_MAPPING_IPV4 test_cilium_snat_v4_external
#define SNAT_MAPPING_IPV4_SIZE 524288
#define NODEPORT_NEIGH4_SIZE 524288
#endif /* ENABLE_NODEPORT */
#define CAPTURE4_RULES cilium_capture4_rules
#define CAPTURE4_SIZE 16384
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
#ifdef ENABLE_NODEPORT
#define SNAT_MAPPING_IPV6 test_cilium_snat_v6_external
#define SNAT_MAPPING_IPV6_SIZE 524288
#define NODEPORT_NEIGH6_SIZE 524288
#endif /* ENABLE_NODEPORT */
#define CAPTURE6_RULES cilium_capture6_rules
#define CAPTURE6_SIZE 16384
#endif /* ENABLE_IPV6 */

#define ENCAP_GENEVE 1

#define EGRESS_POLICY_MAP test_cilium_egress_gw_policy_v4
#define ENDPOINTS_MAP test_cilium_lxc
#define EVENTS_MAP test_cilium_events
#define SIGNAL_MAP test_cilium_signals
#define METRICS_MAP test_cilium_metrics
#define POLICY_CALL_MAP test_cilium_policy
#define SOCK_OPS_MAP test_sock_ops_map
#define IPCACHE_MAP test_cilium_ipcache
#define ENCRYPT_MAP test_cilium_encrypt_state
#define TUNNEL_MAP test_cilium_tunnel_map
#define EP_POLICY_MAP test_cilium_ep_to_policy
#define LB6_REVERSE_NAT_MAP test_cilium_lb6_reverse_nat
#define LB6_SERVICES_MAP_V2 test_cilium_lb6_services
#define LB6_BACKEND_MAP test_cilium_lb6_backends
#define LB6_REVERSE_NAT_SK_MAP test_cilium_lb6_reverse_sk
#define LB6_REVERSE_NAT_SK_MAP_SIZE 262144
#define LB4_REVERSE_NAT_MAP test_cilium_lb4_reverse_nat
#define LB4_SERVICES_MAP_V2 test_cilium_lb4_services
#define LB4_BACKEND_MAP test_cilium_lb4_backends
#define LB4_REVERSE_NAT_SK_MAP test_cilium_lb4_reverse_sk
#define LB4_REVERSE_NAT_SK_MAP_SIZE 262144
#define LB4_AFFINITY_MAP test_cilium_lb4_affinity
#define LB6_AFFINITY_MAP test_cilium_lb6_affinity
#define LB_AFFINITY_MATCH_MAP test_cilium_lb_affinity_match
#define LB_MAGLEV_LUT_SIZE 32749
#define LB4_MAGLEV_MAP_INNER test_cilium_lb4_maglev_inner
#define LB4_MAGLEV_MAP_OUTER test_cilium_lb4_maglev_outer
#define LB6_MAGLEV_MAP_INNER test_cilium_lb6_maglev_inner
#define LB6_MAGLEV_MAP_OUTER test_cilium_lb6_maglev_outer
#define THROTTLE_MAP test_cilium_throttle
#define THROTTLE_MAP_SIZE 65536
#define ENABLE_ARP_RESPONDER
#define TUNNEL_ENDPOINT_MAP_SIZE 65536
#define ENDPOINTS_MAP_SIZE 65536
#define METRICS_MAP_SIZE 65536
#define CILIUM_NET_MAC  { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x57 } }
#define LB_REDIRECT 1
#define LB_DST_MAC { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x58 } }
#define CILIUM_LB_MAP_MAX_ENTRIES	65536
#define POLICY_MAP_SIZE 16384
#define IPCACHE_MAP_SIZE 512000
#define EGRESS_POLICY_MAP_SIZE 16384
#define POLICY_PROG_MAP_SIZE ENDPOINTS_MAP_SIZE
#define IPV4_FRAG_DATAGRAMS_MAP test_cilium_ipv4_frag_datagrams
#define CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES 8192
#ifndef SKIP_DEBUG
#define LB_DEBUG
#endif
#ifndef MONITOR_AGGREGATION
#define MONITOR_AGGREGATION 5
#endif
#define MTU 1500
#define EPHEMERAL_MIN 32768
#if defined(ENABLE_NODEPORT) || defined(ENABLE_HOST_FIREWALL) || defined(ENABLE_NAT46)
#define CT_MAP_TCP6 test_cilium_ct_tcp6_65535
#define CT_MAP_ANY6 test_cilium_ct_any6_65535
#define CT_MAP_TCP4 test_cilium_ct_tcp4_65535
#define CT_MAP_ANY4 test_cilium_ct_any4_65535
#define CT_MAP_SIZE_TCP 4096
#define CT_MAP_SIZE_ANY 4096
#define CONNTRACK
#define CONNTRACK_ACCOUNTING
#define LB4_HEALTH_MAP test_cilium_lb4_health
#define LB6_HEALTH_MAP test_cilium_lb6_health
#endif /* ENABLE_NODEPORT || ENABLE_HOST_FIREWALL */

#ifdef ENABLE_NODEPORT
#ifdef ENABLE_IPV4
#define NODEPORT_NEIGH4 test_cilium_neigh4
#endif
#ifdef ENABLE_IPV6
#define NODEPORT_NEIGH6 test_cilium_neigh6
#endif
#endif

#ifdef ENABLE_NODEPORT
# define DIRECT_ROUTING_DEV_IFINDEX 0
# ifdef ENABLE_IPV4
#  define IPV4_DIRECT_ROUTING 0
#  define IPV4_RSS_PREFIX IPV4_DIRECT_ROUTING
#  define IPV4_RSS_PREFIX_BITS 32
# endif
# ifdef ENABLE_IPV6
#  define IPV6_DIRECT_ROUTING { .addr = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#  define IPV6_RSS_PREFIX IPV6_DIRECT_ROUTING
#  define IPV6_RSS_PREFIX_BITS 128
# endif
#define IS_L3_DEV(ifindex) false
#endif

#ifdef ENABLE_SRC_RANGE_CHECK
# define LB4_SRC_RANGE_MAP	test_cilium_lb4_source_range
# define LB4_SRC_RANGE_MAP_SIZE	1000
# define LB6_SRC_RANGE_MAP	test_cilium_lb6_source_range
# define LB6_SRC_RANGE_MAP_SIZE	1000
#endif

#ifndef LB_SELECTION
# define LB_SELECTION_RANDOM	1
# define LB_SELECTION_MAGLEV	2
# define LB_SELECTION		LB_SELECTION_RANDOM
#endif

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
