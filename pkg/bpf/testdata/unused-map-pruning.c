#include <bpf/ctx/skb.h>
#include "common.h"

#include <lib/static_data.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 10);
} map_a __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 10);
} map_b __section_maps_btf;

DECLARE_CONFIG(__u32, some_other_config, "Just here to offset the other configs")
DECLARE_CONFIG(bool, use_map_a, "Use map_a")
DECLARE_CONFIG(bool, use_map_b, "Use map_b")

__section("tc")
static int entry() {
        __u32 key = 0;
        __u64 *value = NULL;

        if (CONFIG(use_map_a))
                value = map_lookup_elem(&map_a, &key);

        if (CONFIG(use_map_b))
                value = map_lookup_elem(&map_b, &key);

        if (!value) {
                return -1;
        }

        return 0;
}
