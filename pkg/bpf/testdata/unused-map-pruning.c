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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 10);
} map_static __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 10);
} map_global __section_maps_btf;

DECLARE_CONFIG(bool, use_map_a, "Use map_a")
DECLARE_CONFIG(bool, use_map_b, "Use map_b")
DECLARE_CONFIG(bool, use_map_static, "Use map_static, testing if eliminating all call sites poisons the map pointer")
DECLARE_CONFIG(bool, use_map_global, "Use map_global, testing if we can safely poison map pointers in global functions")

static __noinline
int static_call() {
        __u32 key = 0;
        __u64 *value = NULL;

        value = map_lookup_elem(&map_static, &key);
        if (!value) {
                return -1;
        }

        return 0;
}

__noinline
int global_call() {
        __u32 key = 0;
        __u64 *value = NULL;

        value = map_lookup_elem(&map_global, &key);
        if (!value) {
                return -1;
        }

        return 0;
}

__section("tc")
static int entry() {
        __u32 key = 0;
        __u64 *value = NULL;

        if (CONFIG(use_map_a))
                value = map_lookup_elem(&map_a, &key);

        if (CONFIG(use_map_b))
                value = map_lookup_elem(&map_b, &key);

        if (CONFIG(use_map_static))
                static_call();

        if (CONFIG(use_map_global))
                global_call();

        if (!value) {
                return -1;
        }

        return 0;
}
