/*
 *  Copyright (C) 2018 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
#include <stdint.h>
#include <stdbool.h>


/**
 * update_metrics
 * @direction:	1: Ingress 2: Egress
 * @reason:	reason for forwarding or dropping packet.
            	reason is 0 if packet is being forwarded, else reason
            	is the drop error code.
 * Update the metrics map.
 */
static inline void update_metrics(__u32 bytes, __u8 direction, __u8 reason)
{
    struct metrics_value *entry, newEntry = {};
    struct metrics_key key = {};

    key.reason = reason;
    key.dir    = direction;


    if ((entry = map_lookup_elem(&METRICS_MAP, &key))) {
            entry->count += 1;
            entry->bytes += (__u64)bytes;
    } else {
            newEntry.count = 1;
            newEntry.bytes = (__u64)bytes;
            map_update_elem(&METRICS_MAP, &key, &newEntry, 0);
    }
}

#endif /* __LIB_METRICS__ */
