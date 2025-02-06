/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Data metrics collection functions
 *
 */
#pragma once

#include "common.h"
#include "utils.h"
#include "dbg.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct metrics_key);
	__type(value, struct metrics_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, METRICS_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} cilium_metrics __section_maps_btf;

/**
 * update_metrics
 * @direction:	1: Ingress 2: Egress
 * @reason:	reason for forwarding or dropping packet.
 *		reason is 0 if packet is being forwarded, else reason
 *		is the drop error code.
 * Update the metrics map.
 */
#define update_metrics(bytes, direction, reason) \
		_update_metrics(bytes, direction, reason, __MAGIC_LINE__, __MAGIC_FILE__)
static __always_inline void _update_metrics(__u64 bytes, __u8 direction,
					    __u8 reason, __u16 line, __u8 file)
{
	struct metrics_value *entry, new_entry = {};
	struct metrics_key key = {};

	key.reason = reason;
	key.dir    = direction;
	key.line   = line;
	key.file   = file;

	entry = map_lookup_elem(&cilium_metrics, &key);
	if (entry) {
		entry->count += 1;
		entry->bytes += bytes;
	} else {
		new_entry.count = 1;
		new_entry.bytes = bytes;
		map_update_elem(&cilium_metrics, &key, &new_entry, 0);
	}
}

/**
 * ct_to_metrics_dir
 * @direction:	1: Ingress 2: Egress 3: Service
 * Convert a CT direction into the corresponding one for metrics.
 */
static __always_inline enum metric_dir ct_to_metrics_dir(enum ct_dir ct_dir)
{
	switch (ct_dir) {
	case CT_INGRESS:
		return METRIC_INGRESS;
	case CT_EGRESS:
		return METRIC_EGRESS;
	case CT_SERVICE:
		return METRIC_SERVICE;
	default:
		return 0;
	}
}
