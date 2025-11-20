#include <bpf/ctx/skb.h>
#include "common.h"

#include <lib/static_data.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} unused_map __section_maps_btf;

DECLARE_CONFIG(__u8, dummy, "A dummy config value that's always zero")

__section("tc")
int false_negative() {
        __u32 *value = NULL;

        // The compiler likes to put volatile locals on the stack, which
        // Cilium's branch resolver cannot track, but the verifier can!
        //
        // Since Cilium cannot predict the outcome, it will not poison the map
        // access in the branch. Conversely, the verifier will see that this
        // branch is never taken and will eliminate it. This causes the map to
        // be freed after verification, which freedMaps will detect.
        volatile const __u8 num = 0;
        if ((CONFIG(dummy) + num) == 1) {
                __u32 key = 0;
                value = map_lookup_elem(&unused_map, &key);
        }

        if (!value) {
                return -1;
        }

        return 0;
}
