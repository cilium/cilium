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

NODE_CONFIG(__u16, tunnel_port, "Tunnel port")

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

NODE_CONFIG(bool, hybrid_routing_enabled, "Enable hybrid mode routing based on subnet IDs")
