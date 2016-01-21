package main

/*
#include <linux/unistd.h>
#include <linux/bpf.h>

static __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

void create_bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
		   int max_entries, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
    ptr_bpf_attr->map_type = map_type;
    ptr_bpf_attr->key_size = key_size;
    ptr_bpf_attr->value_size = value_size;
    ptr_bpf_attr->max_entries = max_entries;
}

void create_bpf_update_elem(int fd, const void *key, const void *value,
  unsigned long long flags, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
    ptr_bpf_attr->map_fd = fd;
    ptr_bpf_attr->key = ptr_to_u64(key);
    ptr_bpf_attr->value = ptr_to_u64(value);
    ptr_bpf_attr->flags = flags;
}

void create_bpf_lookup_elem(int fd, const void *key, void *value, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
    ptr_bpf_attr->map_fd = fd;
    ptr_bpf_attr->key = ptr_to_u64(key);
    ptr_bpf_attr->value = ptr_to_u64(value);
}

void create_bpf_delete_elem(int fd, const void *key, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
    ptr_bpf_attr->map_fd = fd;
    ptr_bpf_attr->key = ptr_to_u64(key);
}

void create_bpf_get_next_key(int fd, const void *key, void *next_key, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
    ptr_bpf_attr->map_fd = fd;
    ptr_bpf_attr->key = ptr_to_u64(key);
    ptr_bpf_attr->next_key = ptr_to_u64(next_key);
}

void create_bpf_obj_pin(int fd, const char *pathname, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
    ptr_bpf_attr->pathname = ptr_to_u64(pathname);
    ptr_bpf_attr->bpf_fd = fd;
}

void create_bpf_obj_get(const char *pathname, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
    ptr_bpf_attr->pathname = ptr_to_u64(pathname);
}
*/
import "C"

import (
	"syscall"
	"unsafe"
)

func BPFCreateMap(mapType int, keySize, valueSize, maxEntries uint32) (r1, r2 uintptr, err syscall.Errno) {
	uba := C.union_bpf_attr{}
	C.create_bpf_create_map(
		C.enum_bpf_map_type(mapType),
		C.int(keySize),
		C.int(valueSize),
		C.int(maxEntries),
		unsafe.Pointer(&uba),
	)
	return syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_CREATE,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
}

func BPFUpdateElem(fd uint32, key, value unsafe.Pointer, flags uint64) (r1, r2 uintptr, err syscall.Errno) {
	uba := C.union_bpf_attr{}
	C.create_bpf_lookup_elem(
		C.int(fd),
		key,
		value,
		unsafe.Pointer(&uba),
	)
	return syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_UPDATE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
}

func BPFLookupElem(fd uint32, key, value unsafe.Pointer) (r1, r2 uintptr, err syscall.Errno) {
	uba := C.union_bpf_attr{}
	C.create_bpf_lookup_elem(
		C.int(fd),
		key,
		value,
		unsafe.Pointer(&uba),
	)
	return syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_LOOKUP_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
}

func BPFDeleteElem(fd uint32, key unsafe.Pointer) (r1, r2 uintptr, err syscall.Errno) {
	uba := C.union_bpf_attr{}
	C.create_bpf_delete_elem(
		C.int(fd),
		key,
		unsafe.Pointer(&uba),
	)
	return syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
}

func BPFGetNextKey(fd uint32, key, nextKey unsafe.Pointer) (r1, r2 uintptr, err syscall.Errno) {
	uba := C.union_bpf_attr{}
	C.create_bpf_get_next_key(
		C.int(fd),
		key,
		nextKey,
		unsafe.Pointer(&uba),
	)
	return syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_GET_NEXT_KEY,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
}

func BPFObjPin(fd uint32, pathname string) (r1, r2 uintptr, err syscall.Errno) {
	pathStr := C.CString(pathname)
	uba := C.union_bpf_attr{}
	C.create_bpf_obj_pin(C.int(fd), pathStr, unsafe.Pointer(&uba))
	return syscall.Syscall(
		C.__NR_bpf,
		C.BPF_OBJ_PIN,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
}

func BPFObjGet(pathname string) (r1, r2 uintptr, err syscall.Errno) {
	pathStr := C.CString(pathname)
	uba := C.union_bpf_attr{}
	C.create_bpf_obj_get(pathStr, unsafe.Pointer(&uba))
	return syscall.Syscall(
		C.__NR_bpf,
		C.BPF_OBJ_GET,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
}
