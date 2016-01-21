/* eBPF mini library */

#ifndef __LIBBPF_H
#define __LIBBPF_H

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
		   int max_entries);

int bpf_update_elem(int fd, const void *key, const void *value,
		    unsigned long long flags);
int bpf_lookup_elem(int fd, const void *key, void *value);
int bpf_delete_elem(int fd, const void *key);
int bpf_get_next_key(int fd, const void *key, void *next_key);

int bpf_obj_pin(int fd, const char *pathname);
int bpf_obj_get(const char *pathname);

#endif /* __LIBBPF_H */
