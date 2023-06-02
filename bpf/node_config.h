/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __NODE_CONFIG__
#define __NODE_CONFIG__

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

#define CLUSTER_ID 0

#ifndef NODE_MAC
DEFINE_MAC(NODE_MAC, 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde);
#define NODE_MAC fetch_mac(NODE_MAC)
#endif

#ifndef ROUTER_IP
DEFINE_IPV6(ROUTER_IP, 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0);
#endif

#define HOST_IFINDEX 1
#define CILIUM_IFINDEX 1
#define NATIVE_DEV_MAC_BY_IFINDEX(_) { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 } }

#ifndef HOST_IP
DEFINE_IPV6(HOST_IP, 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0xa, 0x0, 0x2, 0xf, 0xff, 0xff);
#endif

#ifndef SECCTX_FROM_IPCACHE
 DEFINE_U32(SECCTX_FROM_IPCACHE, 1);
 #define SECCTX_FROM_IPCACHE fetch_u32(SECCTX_FROM_IPCACHE)
#endif

#define TUNNEL_PORT 8472
#define TUNNEL_PROTOCOL_VXLAN 1
#define TUNNEL_PROTOCOL_GENEVE 2
#ifndef TUNNEL_PROTOCOL
#define TUNNEL_PROTOCOL TUNNEL_PROTOCOL_VXLAN
#endif

#define HOST_ID 1
#define WORLD_ID 2
#define UNMANAGED_ID 3
#define HEALTH_ID 4
#define INIT_ID 5
#define LOCAL_NODE_ID 6
#define REMOTE_NODE_ID 6
#define KUBE_APISERVER_NODE_ID 7
#define HOST_IFINDEX_MAC { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 } }
#define NODEPORT_PORT_MIN 30000
#define NODEPORT_PORT_MAX 32767
#define NODEPORT_PORT_MIN_NAT (NODEPORT_PORT_MAX + 1)
#define NODEPORT_PORT_MAX_NAT 43835

#define CT_CONNECTION_LIFETIME_TCP	21600
#define CT_CONNECTION_LIFETIME_NONTCP	60
#define CT_SERVICE_LIFETIME_TCP		21600
#define CT_SERVICE_LIFETIME_NONTCP	60
#define CT_SERVICE_CLOSE_REBALANCE	30
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
#define IPV4_ENCRYPT_IFACE 0xfffff50a
# ifdef ENABLE_MASQUERADE
#  define IPV4_SNAT_EXCLUSION_DST_CIDR 0xffff0000
#  define IPV4_SNAT_EXCLUSION_DST_CIDR_LEN 16
# endif /* ENABLE_MASQUERADE */
#ifdef ENABLE_NODEPORT
#define SNAT_MAPPING_IPV4 test_cilium_snat_v4_external
#define PER_CLUSTER_SNAT_MAPPING_IPV4 test_cilium_per_cluster_snat_v4_external
#if defined(ENABLE_CLUSTER_AWARE_ADDRESSING) && defined(ENABLE_INTER_CLUSTER_SNAT)
#define IPV4_INTER_CLUSTER_SNAT 0xfffff50a
#endif
#define SNAT_MAPPING_IPV4_SIZE 524288
#define NODEPORT_NEIGH4_SIZE 524288
#endif /* ENABLE_NODEPORT */
#define CAPTURE4_RULES cilium_capture4_rules
#define CAPTURE4_SIZE 16384
# ifdef ENABLE_HIGH_SCALE_IPCACHE
#  define IPV4_NATIVE_ROUTING_CIDR 0xffff0000
#  define IPV4_NATIVE_ROUTING_CIDR_LEN 16
# endif /* ENABLE_HIGH_SCALE_IPCACHE */
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
#ifdef ENABLE_NODEPORT
#define SNAT_MAPPING_IPV6 test_cilium_snat_v6_external
#define PER_CLUSTER_SNAT_MAPPING_IPV6 test_cilium_per_cluster_snat_v6_external
#define SNAT_MAPPING_IPV6_SIZE 524288
#define NODEPORT_NEIGH6_SIZE 524288
#endif /* ENABLE_NODEPORT */
#define CAPTURE6_RULES cilium_capture6_rules
#define CAPTURE6_SIZE 16384
#endif /* ENABLE_IPV6 */

#define EGRESS_POLICY_MAP test_cilium_egress_gw_policy_v4
#define SRV6_VRF_MAP4 test_cilium_srv6_vrf_v4
#define SRV6_VRF_MAP6 test_cilium_srv6_vrf_v6
#define SRV6_POLICY_MAP4 test_cilium_srv6_policy_v4
#define SRV6_POLICY_MAP6 test_cilium_srv6_policy_v6
#define SRV6_SID_MAP test_cilium_srv6_sid
#define SRV6_STATE_MAP4 test_cilium_srv6_state4
#define SRV6_STATE_MAP6 test_cilium_srv6_state6
#define ENDPOINTS_MAP test_cilium_lxc
#define EVENTS_MAP test_cilium_events
#define SIGNAL_MAP test_cilium_signals
#define METRICS_MAP test_cilium_metrics
#define POLICY_CALL_MAP test_cilium_policy
#define AUTH_MAP test_cilium_auth
#define CONFIG_MAP test_cilium_runtime_config
#define IPCACHE_MAP test_cilium_ipcache
#define NODE_MAP test_cilium_node_map
#define ENCRYPT_MAP test_cilium_encrypt_state
#define TUNNEL_MAP test_cilium_tunnel_map
#define VTEP_MAP test_cilium_vtep_map
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
#define LB4_MAGLEV_MAP_OUTER test_cilium_lb4_maglev_outer
#define LB6_MAGLEV_MAP_OUTER test_cilium_lb6_maglev_outer
#define THROTTLE_MAP test_cilium_throttle
#define THROTTLE_MAP_SIZE 65536
#define ENABLE_ARP_RESPONDER
#define TUNNEL_ENDPOINT_MAP_SIZE 65536
#define VTEP_MAP_SIZE 8
#define ENDPOINTS_MAP_SIZE 65536
#define METRICS_MAP_SIZE 65536
#define CILIUM_NET_MAC  { .addr = { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x57 } }
#define CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES	65536
#define CILIUM_LB_SERVICE_MAP_MAX_ENTRIES	65536
#define CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES	65536
#define CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES	65536
#define CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES	65536
#define CILIUM_LB_MAGLEV_MAP_MAX_ENTRIES	65536
#define POLICY_MAP_SIZE 16384
#define AUTH_MAP_SIZE 512000
#define CONFIG_MAP_SIZE 256
#define IPCACHE_MAP_SIZE 512000
#define NODE_MAP_SIZE 16384
#define SRV6_VRF_MAP_SIZE 16384
#define SRV6_POLICY_MAP_SIZE 16384
#define SRV6_SID_MAP_SIZE 16384
#define SRV6_STATE_MAP_SIZE 16384
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
#if defined(ENABLE_NODEPORT) || defined(ENABLE_HOST_FIREWALL) || defined(ENABLE_NAT_46X64)
#define CT_MAP_TCP6 test_cilium_ct_tcp6_65535
#define CT_MAP_ANY6 test_cilium_ct_any6_65535
#define CT_MAP_TCP4 test_cilium_ct_tcp4_65535
#define CT_MAP_ANY4 test_cilium_ct_any4_65535
#define PER_CLUSTER_CT_TCP6 test_cilium_per_cluster_ct_tcp6
#define PER_CLUSTER_CT_ANY6 test_cilium_per_cluster_ct_any6
#define PER_CLUSTER_CT_TCP4 test_cilium_per_cluster_ct_tcp4
#define PER_CLUSTER_CT_ANY4 test_cilium_per_cluster_ct_any4
#define CT_MAP_SIZE_TCP 4096
#define CT_MAP_SIZE_ANY 4096
#define CONNTRACK_ACCOUNTING
#define LB4_HEALTH_MAP test_cilium_lb4_health
#define LB6_HEALTH_MAP test_cilium_lb6_health
#endif /* ENABLE_NODEPORT || ENABLE_HOST_FIREWALL */
#ifdef ENABLE_HIGH_SCALE_IPCACHE
# define WORLD_CIDRS4_MAP test_cilium_world_cidrs4
# define WORLD_CIDRS4_MAP_SIZE 16384
#endif /* ENABLE_HIGH_SCALE_IPCACHE */

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
#  ifndef IPV4_DIRECT_ROUTING
#   define IPV4_DIRECT_ROUTING 0
#  endif
#  define IPV4_RSS_PREFIX IPV4_DIRECT_ROUTING
#  define IPV4_RSS_PREFIX_BITS 32
# endif
# ifdef ENABLE_IPV6
#  ifndef IPV6_DIRECT_ROUTING
#   define IPV6_DIRECT_ROUTING { .addr = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#  endif
#  define IPV6_RSS_PREFIX IPV6_DIRECT_ROUTING
#  define IPV6_RSS_PREFIX_BITS 128
# endif
#endif

#ifndef IS_L3_DEV
# define IS_L3_DEV(ifindex) false
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
# define LB_SELECTION_FIRST	3
# define LB_SELECTION		LB_SELECTION_RANDOM
#endif

#ifdef ENABLE_WIREGUARD
# define WG_IFINDEX	42
#endif

#ifdef ENABLE_VTEP
# define VTEP_MASK 0xffffff
#endif

#define VLAN_FILTER(ifindex, vlan_id) switch (ifindex) { \
case 116: \
switch (vlan_id) { \
case 4000: \
case 4001: \
return true; \
} \
break; \
case 117: \
switch (vlan_id) { \
case 4003: \
case 4004: \
case 4005: \
return true; \
} \
break; \
} \
return false;

#define CIDR_IDENTITY_RANGE_START ((1 << 24) + 1)
#define CIDR_IDENTITY_RANGE_END   ((1 << 24) + (1<<16) - 1)

#ifndef NAT_46X64_PREFIX_0
# define NAT_46X64_PREFIX_0 0
# define NAT_46X64_PREFIX_1 0
# define NAT_46X64_PREFIX_2 0
# define NAT_46X64_PREFIX_3 0
#endif

#endif /* __NODE_CONFIG__ */
