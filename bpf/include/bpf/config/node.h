/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This file contains node-level configuration data, available to all bpf_*.c
 * objects.
 *
 * See https://docs.cilium.io/en/latest/contributing/development/datapath_config
 * for guidelines and recommendations.
 */

#pragma once

#include <bpf/lb_selection.h>
#include <lib/ipv4_core.h>
#include <lib/ipv6_core.h>
#include <lib/static_data.h>

/* Legacy node config rendered at agent runtime. */
#include <node_config.h>

NODE_CONFIG(__u32, cilium_net_ifindex, "Interface index of the cilium_net device")
NODE_CONFIG(union macaddr, cilium_net_mac, "MAC address of the cilium_net device")
NODE_CONFIG(__u32, cilium_host_ifindex, "Interface index of the cilium_host device")
NODE_CONFIG(union macaddr, cilium_host_mac, "MAC address of the cilium_host device")

NODE_CONFIG(union v4addr, service_loopback_ipv4, "IPv4 source address used for SNAT when a Pod talks to itself over a Service")
NODE_CONFIG(union v4addr, router_ipv4,
	    "Internal IPv4 router address assigned to the cilium_host interface")
NODE_CONFIG(union v6addr, service_loopback_ipv6,
	    "IPv6 source address used for SNAT when a Pod talks to itself over a Service")
NODE_CONFIG(union v6addr, router_ipv6, "Internal IPv6 router address assigned to the cilium_host interface")

NODE_CONFIG(__u32, trace_payload_len, "Length of payload to capture when tracing native packets.")
#define TRACE_PAYLOAD_LEN CONFIG(trace_payload_len) /* Backwards compatibility */

NODE_CONFIG(__u32, trace_payload_len_overlay, "Length of payload to capture when tracing overlay packets.")

NODE_CONFIG(__u32, direct_routing_dev_ifindex, "Index of the interface used to connect nodes in the cluster.")

NODE_CONFIG(bool, supports_fib_lookup_skip_neigh,
	    "Whether or not BPF_FIB_LOOKUP_SKIP_NEIGH is supported.")

NODE_CONFIG(bool, supports_fib_lookup_src,
	    "Whether or not BPF_FIB_LOOKUP_SRC is supported.")

NODE_CONFIG(bool, enable_nodeport_source_lookup,
	    "Enable dynamic source IP resolution for SNAT via linux's routing table.")

NODE_CONFIG(bool, enable_ipip_termination,
	    "Terminate inbound IPIP/IP6IP6 in BPF on netdev ingress for local endpoint outer dst")

NODE_CONFIG(__u8, tracing_ip_option_type, "The IP option type to use for packet tracing")

NODE_CONFIG(bool, policy_deny_response_enabled, "Enable ICMP responses for policy-denied traffic")

NODE_CONFIG(bool, enable_shared_policy, "Enable node-scoped shared policy LPM trie map lookup path")

NODE_CONFIG(__u32, cluster_id, "Cluster ID")

NODE_CONFIG(__u32, cluster_id_bits, "Number of bits of the identity reserved for the Cluster ID")

/* Allow to override the assigned value in tests */
#ifndef DEFAULT_CLUSTER_ID_BITS
#define DEFAULT_CLUSTER_ID_BITS 8
#endif

ASSIGN_CONFIG(__u32, cluster_id_bits, DEFAULT_CLUSTER_ID_BITS)

NODE_CONFIG(bool, enable_conntrack_accounting, "Enable per flow (conntrack) statistics")

NODE_CONFIG(bool, debug_lb, "Enable debugging trace statements for load balancer")

NODE_CONFIG(__u8, lb_default_alg, "Default load-balancer backend selection algorithm")
NODE_CONFIG(bool, lb_selection_per_service,
	    "Enable per-service load-balancer backend selection algorithm")

/*
 * Init lb_default_alg to random to keep the old behaviour,
 * but at the same time allow overriding this value in tests
 */
#ifndef LB_DEFAULT_ALG
#define LB_DEFAULT_ALG LB_SELECTION_RANDOM
#endif

ASSIGN_CONFIG(__u8, lb_default_alg, LB_DEFAULT_ALG)

NODE_CONFIG(__u16, nodeport_port_min, "Nodeport minimum port value.")
NODE_CONFIG(__u16, nodeport_port_max, "Nodeport maximum port value.")
NODE_CONFIG(__u16, nodeport_port_min_nat_ext, "Nodeport NAT extended minimum port value.")
NODE_CONFIG(__u16, nodeport_port_max_nat_ext, "Nodeport NAT extended maximum port value.")

NODE_CONFIG(__u32, hash_init4_seed, "Cluster-wide IPv4 tuple hash seed sourced")
NODE_CONFIG(__u32, hash_init6_seed, "Cluster-wide IPv6 tuple hash seed sourced")

NODE_CONFIG(union v4addr, nat_46x64_prefix, "NAT 46x64 prefix")

NODE_CONFIG(bool, enable_tproxy, "Enable BPF-based proxy redirection")

NODE_CONFIG(__u32, events_map_rate_limit,
	    "The sustained message rate for the BPF events map in messages per second")
NODE_CONFIG(__u32, events_map_burst_limit,
	    "Maximum number of messages that can be written to BPF events map in 1 second")

NODE_CONFIG(bool, enable_endpoint_routes, "Enable per endpoint routes")

NODE_CONFIG(bool, enable_identity_mark, "Enable setting identity mark for local traffic")

NODE_CONFIG(bool, enable_bpf_host_routing, "Enable BPF Host Routing")

NODE_CONFIG(bool, encryption_strict_ingress, "Enable strict encryption for ingress traffic")

NODE_CONFIG(__u8, monitor_aggregation, "Level of aggregation for monitor events")

NODE_CONFIG(union v4addr, ipv4_inter_cluster_snat,
	    "Node IPv4 address used as the source for inter-cluster SNAT")

struct ct_timeout_config {
	/* Lifetime of non-service TCP conntrack entries in seconds. */
	__u32 connection_lifetime_tcp;
	/* Lifetime of non-service non-TCP conntrack entries in seconds. */
	__u32 connection_lifetime_non_tcp;
	/* Lifetime of TCP service conntrack entries in seconds. */
	__u32 service_lifetime_tcp;
	/* Lifetime of non-TCP service conntrack entries in seconds. */
	__u32 service_lifetime_non_tcp;
	/* Grace period before a closed TCP service connection may be rebalanced, in seconds. */
	__u32 service_close_rebalance;
	/* Lifetime of TCP conntrack entries that have only seen SYN packets, in seconds. */
	__u32 syn_timeout;
	/* Lifetime of closed TCP conntrack entries in seconds. */
	__u32 close_timeout;
};

NODE_CONFIG(struct ct_timeout_config, ct_timeouts, "Conntrack timeout configuration")
ASSIGN_CONFIG(struct ct_timeout_config, ct_timeouts, {
	.connection_lifetime_tcp = 21600,
	.connection_lifetime_non_tcp = 60,
	.service_lifetime_tcp = 21600,
	.service_lifetime_non_tcp = 60,
	.service_close_rebalance = 30,
	.syn_timeout = 60,
	.close_timeout = 10,
})

NODE_CONFIG(union v4addr, ipv4_direct_routing,
	    "IPv4 address of the device used for direct routing between nodes")
NODE_CONFIG(union v6addr, ipv6_direct_routing,
	    "IPv6 address of the device used for direct routing between nodes")

struct ipv4_snat_exclusion_prefix {
	union v4addr dst_addr;
	__u8 bits;
	bool enabled;
};

NODE_CONFIG(struct ipv4_snat_exclusion_prefix, ipv4_snat_exclusion,
	    "IPv4 destination prefix excluded from SNAT")

struct ipv6_snat_exclusion_prefix {
	union v6addr dst_addr;
	union v6addr dst_mask;
	bool enabled;
};

NODE_CONFIG(struct ipv6_snat_exclusion_prefix, ipv6_snat_exclusion,
	    "IPv6 destination prefix excluded from SNAT")

NODE_CONFIG(__u32, encap4_ifindex,
	    "Interface index of the IPv4 IPIP encapsulation device")
NODE_CONFIG(__u32, encap6_ifindex,
	    "Interface index of the IPv6 IPIP encapsulation device")
