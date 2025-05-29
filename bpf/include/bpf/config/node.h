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
