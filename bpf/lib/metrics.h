/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2020 Authors of Cilium */

/*
 * Data metrics collection functions
 *
 */
#ifndef __LIB_METRICS__
#define __LIB_METRICS__

#include "common.h"
#include "utils.h"
#include "maps.h"
#include "dbg.h"

/**
 * update_metrics
 * @direction:	1: Ingress 2: Egress
 * @reason:	reason for forwarding or dropping packet.
 *		reason is 0 if packet is being forwarded, else reason
 *		is the drop error code.
 * Update the metrics map.
 */
static __always_inline void update_metrics(__u32 bytes, __u8 direction,
					   __u8 reason)
{
	struct metrics_value *entry, newEntry = {};
	struct metrics_key key = {};

	key.reason = reason;
	key.dir    = direction;


	entry = map_lookup_elem(&METRICS_MAP, &key);
	if (entry) {
		entry->count += 1;
		entry->bytes += (__u64)bytes;
	} else {
		newEntry.count = 1;
		newEntry.bytes = (__u64)bytes;
		map_update_elem(&METRICS_MAP, &key, &newEntry, 0);
	}
}

/**
 * ct_to_metrics_dir
 * @ct_dir: CT direction. Should be either CT_INGRESS, CT_EGRESS or CT_SERVICE.
 *
 * Convert a CT_* direction into the corresponding METRIC one.
 * Returns 0 if an invalid direction is passed.
 */
static __always_inline int ct_to_metrics_dir(int ct_dir)
{
	switch (ct_dir) {
	case CT_INGRESS:
		return METRIC_INGRESS;
	case CT_EGRESS:
		return METRIC_EGRESS;
	case CT_SERVICE:
		return METRIC_SERVICE;
	}

	return 0;
}

#endif /* __LIB_METRICS__ */
