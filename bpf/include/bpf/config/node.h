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

NODE_CONFIG(union v4addr, service_loopback_ipv4, "IPv4 source address used for SNAT when a Pod talks to itself over a Service")
NODE_CONFIG(union v6addr, router_ipv6, "Internal IPv6 router address assigned to the cilium_host interface")

NODE_CONFIG(__u32, trace_payload_len, "Length of payload to capture when tracing native packets.")
#define TRACE_PAYLOAD_LEN CONFIG(trace_payload_len) /* Backwards compatibility */

NODE_CONFIG(__u32, trace_payload_len_overlay, "Length of payload to capture when tracing overlay packets.")

NODE_CONFIG(bool, drop_traffic_to_virtual_ips, "Drop traffic to non-existent ports on virtual IPs")

/* This CONFIG is used to control ICMP echo reply functionality for virtual IPs.
 * When enabled, virtual service IPs will respond to ICMP echo requests (ping)
 * making them appear reachable for network diagnostics.
 */
NODE_CONFIG(bool, reply_to_icmp_echo_on_virtual_ips, "Reply to ICMP echo requests on virtual IPs")
