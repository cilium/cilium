#include "common.h"

static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, 10);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} upgraded_map __section_maps_btf;

__section("tc")
int dummy(void *ctx) {
        __u32 key = 0;
        bpf_map_lookup_elem(&upgraded_map, &key);
        return 0;
}
