/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#ifdef ENABLE_ACTIVE_CONNECTION_TRACKING
struct lb_act_key {
	__u16 svc_id;
	__u8 zone;
	__u8 pad;
};

struct lb_act_value {
	__u32 opened;
	__u32 closed;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct lb_act_key);
	__type(value, struct lb_act_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_ACT_MAP_MAX_ENTRIES);
} LB_ACT_MAP __section_maps_btf;

static __always_inline void _lb_act_conn_closed(__u16 svc_id, __u8 zone)
{
	struct lb_act_key key = { .svc_id = svc_id, .zone = zone };
	struct lb_act_value *lookup;

	if (key.zone == 0)
		return;
	lookup = map_lookup_elem(&LB_ACT_MAP, &key);
	if (!lookup)
		return;
	__sync_fetch_and_add(&lookup->closed, 1);
}

static __always_inline void _lb_act_conn_open(__u16 svc_id, __u8 zone)
{
	struct lb_act_key key = { .svc_id = svc_id, .zone = zone };
	struct lb_act_value val;
	struct lb_act_value *lookup;

	if (key.zone == 0)
		return;
	lookup = map_lookup_elem(&LB_ACT_MAP, &key);
	if (!lookup) {
		val.opened = 1;
		val.closed = 0;
		map_update_elem(&LB_ACT_MAP, &key, &val, BPF_ANY);
		return;
	}
	__sync_fetch_and_add(&lookup->opened, 1);
}
#endif /* ENABLE_ACTIVE_CONNECTION_TRACKING */
