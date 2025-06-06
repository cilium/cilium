/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <bpf/section.h>
#include <bpf/loader.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct device_key);
	__type(value, struct device_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, DEVICE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_device_map  __section_maps_btf;

static __always_inline struct device_value *
lookup_device(__u32 ifindex)
{
	struct device_key key = {};

	key.ifindex = ifindex;

	return map_lookup_elem(&cilium_device_map, &key);
}

static __always_inline bool
is_l3_device(__u32 ifindex)
{
	struct device_value *device_value;

	device_value = lookup_device(ifindex);
	if (!device_value)
		return false;
	return device_value->l3 > 0;
}

static __always_inline union macaddr
*device_mac(__u32 ifindex)
{
	struct device_value *device_value;

	device_value = lookup_device(ifindex);
	if (!device_value)
		return NULL;
	return &device_value->mac;
}
