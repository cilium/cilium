/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <lib/static_data.h>

/* VLAN_FILTER_SLOTS must match VLANFilterSlots in pkg/datapath/config/host.go. */
#define VLAN_FILTER_SLOTS 5

/* Slots for --vlan-bpf-bypass: 0 = allow all VLANs, 0xFFFF = unused. */
DECLARE_CONFIG(__u16, vlan_filter_id_0, "--vlan-bpf-bypass slot 0; 0xFFFF = unused")
DECLARE_CONFIG(__u16, vlan_filter_id_1, "--vlan-bpf-bypass slot 1; 0xFFFF = unused")
DECLARE_CONFIG(__u16, vlan_filter_id_2, "--vlan-bpf-bypass slot 2; 0xFFFF = unused")
DECLARE_CONFIG(__u16, vlan_filter_id_3, "--vlan-bpf-bypass slot 3; 0xFFFF = unused")
DECLARE_CONFIG(__u16, vlan_filter_id_4, "--vlan-bpf-bypass slot 4; 0xFFFF = unused")

/* Scan vlan_filter_id_* slots; 0xFFFF terminates, 0 allows all. ifindex is
 * unused since each bpf_host object is loaded per-device.
 */
static __always_inline bool allow_vlan(__u32 __maybe_unused ifindex, __u32 vlan_id)
{
	__u16 ids[VLAN_FILTER_SLOTS] = {
		CONFIG(vlan_filter_id_0), CONFIG(vlan_filter_id_1),
		CONFIG(vlan_filter_id_2), CONFIG(vlan_filter_id_3),
		CONFIG(vlan_filter_id_4),
	};

#pragma unroll
	for (int i = 0; i < VLAN_FILTER_SLOTS; i++) {
		if (ids[i] == 0xFFFF)
			return false;
		if (ids[i] == 0 || ids[i] == (__u16)vlan_id)
			return true;
	}

	return false;
}
