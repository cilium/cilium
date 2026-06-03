/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/*
 *   **** WARNING, THIS FILE IS DEPRECATED, DO NOT ADD NEW CONFIG HERE ****
 *
 * For adding new configuration to the datapath, see the documentation at
 * https://docs.cilium.io/en/latest/contributing/development/datapath_config.
 *
 * Variables in this file will gradually be migrated to the new format, and this
 * file will eventually be removed.
 */
#include <lib/static_data.h>

#define LRU_MEM_FLAVOR 0

#define CT_REPORT_INTERVAL		5
#ifndef CT_REPORT_FLAGS
# define CT_REPORT_FLAGS		0xff
#endif

#define SNAT_MAPPING_IPV4_SIZE 524288
#define SNAT_MAPPING_IPV6_SIZE 524288

#ifdef ENABLE_IPV6
#ifdef ENABLE_NODEPORT
#endif /* ENABLE_NODEPORT */
#endif /* ENABLE_IPV6 */

#define NODEPORT_NEIGH4_SIZE 524288
#define NODEPORT_NEIGH6_SIZE 524288

#define SNAT_COLLISION_RETRIES 32

#define POLICY_STATS_MAP_SIZE 200
#define LB6_REVERSE_NAT_SK_MAP_SIZE 262144
#define LB4_REVERSE_NAT_SK_MAP_SIZE 262144

#define LB_MAGLEV_LUT_SIZE 32749
#define VTEP_MAP_SIZE 8
#define ENDPOINTS_MAP_SIZE 65536
#define METRICS_MAP_SIZE 65536
#define CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES	65536
#define CILIUM_LB_SERVICE_MAP_MAX_ENTRIES	65536
#define CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES	65536
#define CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES	65536
#define CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES	65536
#define CILIUM_LB_MAGLEV_MAP_MAX_ENTRIES	65536
#define CILIUM_LB_SKIP_MAP_MAX_ENTRIES		100
#define POLICY_MAP_SIZE 16384
#define IPCACHE_MAP_SIZE 512000
#define NODE_MAP_SIZE 16384
#define EGRESS_POLICY_MAP_SIZE 16384
#define SRV6_VRF_MAP_SIZE 16384
#define SRV6_POLICY_MAP_SIZE 16384
#define SRV6_SID_MAP_SIZE 16384
#define L2_RESPONDER_MAP4_SIZE 4096
#define L2_RESPONDER_MAP6_SIZE 4096
#define POLICY_PROG_MAP_SIZE ENDPOINTS_MAP_SIZE
#define CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES 8192
#define CILIUM_IPV6_FRAG_MAP_MAX_ENTRIES 8192

#define CT_MAP_SIZE_TCP 4096
#define CT_MAP_SIZE_ANY 4096

#define LB4_SRC_RANGE_MAP_SIZE	1000
#define LB6_SRC_RANGE_MAP_SIZE	1000

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

/*
 *   **** WARNING, THIS FILE IS DEPRECATED, SEE COMMENT AT THE TOP ****
 */
