/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <bpf/section.h>
#include <bpf/loader.h>

#include "eth.h"

struct device_state {
	union macaddr mac;
	__u8 l3:1;
	__u8 pad0:7;
	__u8 pad1;
	__u16 pad2;
	__u32 pad3;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct device_state);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 4096);
} cilium_devices __section_maps_btf;

static __always_inline struct device_state *
device_state_lookup(__u32 ifindex)
{
	return map_lookup_elem(&cilium_devices, &ifindex);
}

static __always_inline bool
device_is_l3(__u32 ifindex)
{
	struct device_state *state = device_state_lookup(ifindex);

	return state ? state->l3 : false;
}

static __always_inline union macaddr
*device_mac(__u32 ifindex)
{
	struct device_state *state;

	state = device_state_lookup(ifindex);
	if (!state)
		return NULL;
	return &state->mac;
}
