#pragma once

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, int);
	__uint(max_entries, 1);
} seq __section_maps_btf;

static int inc()
{
	__u32 zero = 0;
	int *v;

	v = map_lookup_elem(&seq, &zero);
	if (!v)
		return 0;

	return ++(*v);
}

