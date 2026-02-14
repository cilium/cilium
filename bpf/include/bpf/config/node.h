/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This file contains node-level configuration data, available to all bpf_*.c
 * objects.
 *
 * See https://docs.cilium.io/en/latest/contributing/development/datapath_config
 * for guidelines and recommendations.
 */

#pragma once

#include <lib/static_data.h>

/* Legacy node config rendered at agent runtime. */
#include <node_config.h>

NODE_CONFIG(__u32, cilium_net_ifindex, "Interface index of the cilium_net device")
NODE_CONFIG(union macaddr, cilium_net_mac, "MAC address of the cilium_net device")
NODE_CONFIG(__u32, cilium_host_ifindex, "Interface index of the cilium_host device")
NODE_CONFIG(union macaddr, cilium_host_mac, "MAC address of the cilium_host device")

NODE_CONFIG(union v4addr, service_loopback_ipv4, "IPv4 source address used for SNAT when a Pod talks to itself over a Service")
NODE_CONFIG(union v6addr, service_loopback_ipv6,
	    "IPv6 source address used for SNAT when a Pod talks to itself over a Service")
NODE_CONFIG(union v6addr, router_ipv6, "Internal IPv6 router address assigned to the cilium_host interface")

NODE_CONFIG(__u32, trace_payload_len, "Length of payload to capture when tracing native packets.")
#define TRACE_PAYLOAD_LEN CONFIG(trace_payload_len) /* Backwards compatibility */

NODE_CONFIG(__u32, trace_payload_len_overlay, "Length of payload to capture when tracing overlay packets.")

NODE_CONFIG(__u32, direct_routing_dev_ifindex, "Index of the interface used to connect nodes in the cluster.")

NODE_CONFIG(bool, supports_fib_lookup_skip_neigh,
	    "Whether or not BPF_FIB_LOOKUP_SKIP_NEIGH is supported.")

NODE_CONFIG(__u8, tracing_ip_option_type, "The IP option type to use for packet tracing")

NODE_CONFIG(bool, policy_deny_response_enabled, "Enable ICMP responses for policy-denied traffic")

NODE_CONFIG(__u32, cluster_id, "Cluster ID")

NODE_CONFIG(__u32, cluster_id_bits, "Number of bits of the identity reserved for the Cluster ID")

/* Allow to override the assigned value in tests */
#ifndef DEFAULT_CLUSTER_ID_BITS
#define DEFAULT_CLUSTER_ID_BITS 8
#endif

ASSIGN_CONFIG(__u32, cluster_id_bits, DEFAULT_CLUSTER_ID_BITS)

NODE_CONFIG(bool, enable_conntrack_accounting, "Enable per flow (conntrack) statistics")

NODE_CONFIG(bool, debug_lb, "Enable debugging trace statements for load balancer")

NODE_CONFIG(__u16, nodeport_port_min, "Nodeport minimum port value.")
NODE_CONFIG(__u16, nodeport_port_max, "Nodeport maximum port value.")

NODE_CONFIG(__u32, hash_init4_seed, "Cluster-wide IPv4 tuple hash seed sourced")
NODE_CONFIG(__u32, hash_init6_seed, "Cluster-wide IPv6 tuple hash seed sourced")

NODE_CONFIG(__u32, events_map_rate_limit,
	    "The sustained message rate for the BPF events map in messages per second")
NODE_CONFIG(__u32, events_map_burst_limit,
	    "Maximum number of messages that can be written to BPF events map in 1 second")

NODE_CONFIG(union v4addr, nat_46x64_prefix, "NAT 46x64 prefix")
