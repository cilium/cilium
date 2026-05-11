/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* This configuration data is specific to workload endpoints (bpf_host.c). Do not
 * import into any other program.
 */

#pragma once

#include <lib/static_data.h>

#include <linux/if_ether.h>
/* Allow ETH_HLEN to be overridden from tests. Careful, lib/eth.h contains
 * another ifndef-guarded definition, so the one here needs to go first.
 */
#ifndef ETH_HLEN
/* Make the ethernet header length configurable only on bpf_host since it can be
 * attached to different kinds of interfaces, like external devices, cilium_host
 * and cilium_net. Other programs have this value hardcoded, but here it can be
 * set to 0 from user space if attached to an L2-less external device.
 */
DECLARE_CONFIG(__u8, eth_header_length, "Length of the Ethernet header on this device. May be set to zero on L2-less devices. (default __ETH_HLEN)")
ASSIGN_CONFIG(__u8, eth_header_length, __ETH_HLEN)
#define ETH_HLEN CONFIG(eth_header_length)
#endif

/* --vlan-bpf-bypass allowlist. Each slot holds a VLAN ID to bypass BPF
 * processing; 0 means allow all VLAN-tagged traffic; 0xFFFF means unused.
 * Slots are checked in order and the search stops at the first 0xFFFF.
 */
#define VLAN_FILTER_SLOTS 6
DECLARE_CONFIG(__u16, vlan_filter_id_0, "--vlan-bpf-bypass slot 0; 0 = allow all VLANs, 0xFFFF = unused")
DECLARE_CONFIG(__u16, vlan_filter_id_1, "--vlan-bpf-bypass slot 1; 0xFFFF = unused")
DECLARE_CONFIG(__u16, vlan_filter_id_2, "--vlan-bpf-bypass slot 2; 0xFFFF = unused")
DECLARE_CONFIG(__u16, vlan_filter_id_3, "--vlan-bpf-bypass slot 3; 0xFFFF = unused")
DECLARE_CONFIG(__u16, vlan_filter_id_4, "--vlan-bpf-bypass slot 4; 0xFFFF = unused")
DECLARE_CONFIG(__u16, vlan_filter_id_5, "--vlan-bpf-bypass slot 5; 0xFFFF = unused")
ASSIGN_CONFIG(__u16, vlan_filter_id_0, 0xFFFF)
ASSIGN_CONFIG(__u16, vlan_filter_id_1, 0xFFFF)
ASSIGN_CONFIG(__u16, vlan_filter_id_2, 0xFFFF)
ASSIGN_CONFIG(__u16, vlan_filter_id_3, 0xFFFF)
ASSIGN_CONFIG(__u16, vlan_filter_id_4, 0xFFFF)
ASSIGN_CONFIG(__u16, vlan_filter_id_5, 0xFFFF)
