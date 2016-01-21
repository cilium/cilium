/* eBPF mini library */

#include <linux/unistd.h>
#include <linux/bpf.h>

#include "libbpf.h"

static __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
#ifdef __NR_bpf
	return syscall(__NR_bpf, cmd, attr, size);
#else
	fprintf(stderr, "No bpf syscall, kernel headers too old?\n");
	errno = ENOSYS;
	return -1;
#endif
}

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
		   int max_entries)
{
	union bpf_attr attr = {
		.map_type	= map_type,
		.key_size	= key_size,
		.value_size	= value_size,
		.max_entries	= max_entries
	};

	return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

int bpf_update_elem(int fd, const void *key, const void *value,
		    unsigned long long flags)
{
	union bpf_attr attr = {
		.map_fd		= fd,
		.key		= ptr_to_u64(key),
		.value		= ptr_to_u64(value),
		.flags		= flags,
	};

	return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_lookup_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr = {
		.map_fd		= fd,
		.key		= ptr_to_u64(key),
		.value		= ptr_to_u64(value),
	};

	return bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_delete_elem(int fd, const void *key)
{
	union bpf_attr attr = {
		.map_fd		= fd,
		.key		= ptr_to_u64(key),
	};

	return bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

int bpf_get_next_key(int fd, const void *key, void *next_key)
{
	union bpf_attr attr = {
		.map_fd		= fd,
		.key		= ptr_to_u64(key),
		.next_key	= ptr_to_u64(next_key),
	};

	return bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

int bpf_obj_pin(int fd, const char *pathname)
{
	union bpf_attr attr = {
		.pathname	= ptr_to_u64(pathname),
		.bpf_fd		= fd,
	};

	return bpf(BPF_OBJ_PIN, &attr, sizeof(attr));
}

int bpf_obj_get(const char *pathname)
{
	union bpf_attr attr = {
		.pathname	= ptr_to_u64(pathname),
	};

	return bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}
