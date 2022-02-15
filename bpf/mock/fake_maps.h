/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright Authors of Cilium */

// library for user-space map emulation
// It emulates the eBPF map operations in the user space by wrapping up the raw
// hashmap functions.

#include "hashmap.h"

typedef HASHMAP(void, void) hashmap_void_t;


// Get the number of entries inside map.
size_t fake_get_size(hashmap_void_t *map) {
  return hashmap_size(map);
}

// Initiate map with given length of keys and capacity.
void fake_init_map(hashmap_void_t *map, size_t (*hash)(const void *key), int (*compare)(const void *a, const void *b)) {
  hashmap_init(map, hash, compare);
}

// Loop up the value of given key.
void *fake_lookup_elem(hashmap_void_t *map, const void *key)
{
  return hashmap_get(map, key);
}

// Update the value of given key.
int fake_update_elem(hashmap_void_t *map, const void *key, const void *value, __u32 flags,
		     size_t size)
{
  void *entry = hashmap_get(map, key);
  if (entry == NULL && hashmap_size(map) >= size) {
      printf("Update failed: Map is full\n");
      return -1;
    }

  int r = hashmap_put(map, key, (void *)value);
  if (r == -EEXIST) {
    if (flags == BPF_NOEXIST) return -1;
    hashmap_remove(map, key);
    hashmap_put(map, key, (void *)value);
    return 0;
  } else if (r == 0) {
    if (flags == BPF_EXIST) {
      hashmap_remove(map, key);
      return -1;
    }
    return 0;
  }

  return r;
}

// Delete given key.
int fake_delete_elem(hashmap_void_t *map, const void *key)
{
  return (int)hashmap_remove(map, key);
}
