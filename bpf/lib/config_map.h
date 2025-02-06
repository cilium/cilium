/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <bpf/section.h>
#include <bpf/loader.h>

/*
 * cilium_runtime_config is a global pinned array containing runtime
 * configuration information for the datapath. It is shared across all Cilium
 * BPF programs on the node.
 *
 * Each element in the array is a 64-bit integer, the meaning of which is
 * described by enum runtime_config. Use config_get() and config_set() to
 * interact with the map.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CONFIG_MAP_SIZE);
} cilium_runtime_config __section_maps_btf;

/*
 * Runtime configuration items for the datapath.
 */
enum runtime_config {
	RUNTIME_CONFIG_UTIME_OFFSET = 0, /* Index to Unix time offset in 512 ns units */
	/* Last monotonic time, periodically set by the agent to
	 * tell the datapath its still updating maps
	 */
	RUNTIME_CONFIG_AGENT_LIVENESS = 1,
};

/*
 * config_get() returns the value of the runtime configuration item at the given
 * index. If the index is not found, it returns 0.
 */
static __always_inline __u64 config_get(enum runtime_config index)
{
	__u64 *val = map_lookup_elem(&cilium_runtime_config, &index);

	if (likely(val))
		return *val;

	return 0;
}

/*
 * config_set() sets the value of the runtime configuration item at the given
 * index to the given value.
 */
static __always_inline void config_set(enum runtime_config index, __u64 value)
{
	map_update_elem(&cilium_runtime_config, &index, &value, BPF_ANY);
}
