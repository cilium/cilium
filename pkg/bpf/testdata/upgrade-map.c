#include <bpf/ctx/skb.h>
#include "common.h"

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, 10);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} upgraded_map __section_maps_btf;

__section_entry
int dummy(void *ctx) {
        return 0;
}
