/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This file is a replacement for ep_config.h which replaces global data
 * With pre-defined macros since our test suite doesn't perform global data
 * inlining at the moment.
 */

#ifndef ___EP_CONFIG____
#define ___EP_CONFIG____

#ifndef LXC_IP
#define LXC_IP_1 bpf_cpu_to_be64( \
		(__u64)(0xbe) << 56 | (__u64)(0xef) << 48 | (__u64)(0) << 40 | (__u64)(0) << 32 | \
		(0) << 24 | (0) << 16 | (0) << 8 | (0x01))
#define LXC_IP_2 bpf_cpu_to_be64( \
		(__u64)(0) << 56 | (__u64)(0) << 48 | (__u64)(0) << 40 | (__u64)(0x01) << 32 | \
		(0x01) << 24 | (0x65) << 16 | (0x82) << 8 | (0xbc))
#define LXC_IP { { LXC_IP_1, LXC_IP_2 } }
#endif /* LXC_IP */

#ifndef LXC_IPV4
#define LXC_IPV4 0x10203040
#endif /* LXC_IPV4 */

/*
 * Both the LXC_ID and the HOST_EP_ID are defined here to ease compile testing,
 * but in the actual header files, only one of them will be present.
 */
#ifndef LXC_ID
#define LXC_ID 0x2A
#endif

#ifndef SECLABEL
#define SECLABEL 0xfffff
#endif

#ifndef SECLABEL_NB
#define SECLABEL_NB 0xfffff
#endif

#ifndef POLICY_VERDICT_LOG_FILTER
#define POLICY_VERDICT_LOG_FILTER 0xffff
#endif

#ifndef HOST_EP_ID
#define HOST_EP_ID 0x1092
#endif

#ifndef POLICY_MAP
#define POLICY_MAP test_cilium_policy_65535
#endif

#ifndef SKIP_DEBUG
#define DEBUG
#endif

#define DROP_NOTIFY
#define TRACE_NOTIFY
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
#define CALLS_MAP test_cilium_calls_65535
#define CUSTOM_CALLS_MAP test_cilium_calls_custom_65535
#define LOCAL_DELIVERY_METRICS
#define CONNTRACK_ACCOUNTING
#define DIRECT_ROUTING_DEV_IFINDEX 0

#endif /* ___EP_CONFIG____ */

#define DEFINE_MAC(NAME, a1, a2, a3, a4, a5, a6)			\
DEFINE_U32_I(NAME, 1) = (a1) << 24 | (a2) << 16 | (a3) << 8 | (a4);	\
DEFINE_U32_I(NAME, 2) =                            (a5) << 8 | (a6)

#ifndef NODE_MAC
#define NODE_MAC_1 (0xde) << 24 | (0xad) << 16 | (0xbe) << 8 | (0xef)
#define NODE_MAC_2 (0xc0) << 8 | (0xde)
#define NODE_MAC { { NODE_MAC_1, NODE_MAC_2 } }
#endif

#ifndef ROUTER_IP
#define ROUTER_IP_1 bpf_htonl((0xbe) << 24 | (0xef) << 16 | (0) << 8 | (0))
#define ROUTER_IP_2 bpf_htonl((0) << 24 | (0) << 16 | (0) << 8 | (0x01))
#define ROUTER_IP_3 bpf_htonl((0) << 24 | (0) << 16 | (0) << 8 | (0x01))
#define ROUTER_IP_4 bpf_htonl((0x0) << 24 | (0x1) << 16 | (0x0) << 8 | (0x0))
#define ROUTER_IP { { ROUTER_IP_1, ROUTER_IP_2, ROUTER_IP_3, ROUTER_IP_4 } }
#endif

#ifndef HOST_IP
#define HOST_IP_1 bpf_htonl((0xbe) << 24 | (0xef) << 16 | (0) << 8 | (0))
#define HOST_IP_2 bpf_htonl((0) << 24 | (0) << 16 | (0) << 8 | (0x01))
#define HOST_IP_3 bpf_htonl((0) << 24 | (0) << 16 | (0xa) << 8 | (0x00))
#define HOST_IP_4 bpf_htonl((0x2) << 24 | (0xf) << 16 | (0xff) << 8 | (0xff))
#define HOST_IP { { HOST_IP_1, HOST_IP_2, HOST_IP_3, HOST_IP_4 } }
#endif
