/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static long __clear_map_cb_fn(void *map, const void *key,
			      const void __maybe_unused *value, const void __maybe_unused *ctx)
{
    map_delete_elem(map, key);

    return 0;
}

static __u64 clear_map(void *map)
{
    return for_each_map_elem(map, __clear_map_cb_fn, NULL, 0);
}
