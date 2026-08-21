/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#ifdef ENABLE_LB_LEAST_CONNECTION

#if LB_LEAST_CONNECTION_CHOICES < 2 || LB_LEAST_CONNECTION_CHOICES > 4
#error "LB_LEAST_CONNECTION_CHOICES must be between 2 and 4"
#endif

#include <linux/bpf.h>
#include <bpf/loader.h>

struct lb_lc_key {
	__u32 backend_id;
	__u16 svc_id;
	__u16 pad;
};

struct lb_lc_value {
	__u32 opened;
	__u32 closed;
};

struct lb_lc_sock_value {
	__u32 backend_id;
	__u16 svc_id;
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb_lc_key);
	__type(value, struct lb_lc_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_SERVICE_MAP_MAX_ENTRIES);
} cilium_lb_lc __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb_lc_key);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_SERVICE_MAP_MAX_ENTRIES);
} cilium_lb_lc_gc __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct lb_lc_sock_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB4_REVERSE_NAT_SK_MAP_SIZE);
} cilium_lb_lc_sock __section_maps_btf;

static __always_inline __u32
lb_lc_active_connections(__u16 svc_id, __u32 backend_id)
{
	struct lb_lc_key key = {
		.backend_id = backend_id,
		.svc_id = svc_id,
	};
	struct lb_lc_value *counter;
	__u32 *gc_closed;
	__u32 closed;

	counter = map_lookup_elem(&cilium_lb_lc, &key);
	if (!counter)
		return 0;

	closed = READ_ONCE(counter->closed);
	gc_closed = map_lookup_elem(&cilium_lb_lc_gc, &key);
	if (gc_closed)
		closed += *gc_closed;

	if (closed >= READ_ONCE(counter->opened))
		return 0;
	return READ_ONCE(counter->opened) - closed;
}

static __always_inline void
lb_lc_conn_open(__u16 svc_id, __u32 backend_id)
{
	struct lb_lc_key key = {
		.backend_id = backend_id,
		.svc_id = svc_id,
	};
	struct lb_lc_value initial = {
		.opened = 1,
	};
	struct lb_lc_value *counter;

	counter = map_lookup_elem(&cilium_lb_lc, &key);
	if (counter) {
		__sync_fetch_and_add(&counter->opened, 1);
		return;
	}

	if (map_update_elem(&cilium_lb_lc, &key, &initial, BPF_NOEXIST) == 0)
		return;

	counter = map_lookup_elem(&cilium_lb_lc, &key);
	if (counter)
		__sync_fetch_and_add(&counter->opened, 1);
}

static __always_inline void
lb_lc_conn_closed(__u16 svc_id, __u32 backend_id)
{
	struct lb_lc_key key = {
		.backend_id = backend_id,
		.svc_id = svc_id,
	};
	struct lb_lc_value *counter;

	counter = map_lookup_elem(&cilium_lb_lc, &key);
	if (counter)
		__sync_fetch_and_add(&counter->closed, 1);
}

static __always_inline void
lb_lc_sock_open(__u64 cookie, __u16 svc_id, __u32 backend_id)
{
	struct lb_lc_sock_value assignment = {
		.backend_id = backend_id,
		.svc_id = svc_id,
	};

	if (map_update_elem(&cilium_lb_lc_sock, &cookie, &assignment,
			    BPF_NOEXIST) == 0)
		lb_lc_conn_open(svc_id, backend_id);
}

static __always_inline void
lb_lc_sock_closed(__u64 cookie)
{
	struct lb_lc_sock_value *assignment;
	struct lb_lc_sock_value value;

	assignment = map_lookup_elem(&cilium_lb_lc_sock, &cookie);
	if (!assignment)
		return;

	value = *assignment;
	if (map_delete_elem(&cilium_lb_lc_sock, &cookie) == 0)
		lb_lc_conn_closed(value.svc_id, value.backend_id);
}

#endif /* ENABLE_LB_LEAST_CONNECTION */
