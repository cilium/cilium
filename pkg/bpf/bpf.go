// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bpf

/*
#cgo CFLAGS: -I../../bpf/include
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <sys/resource.h>

#if !defined __NR_bpf && defined CI_BUILD
#define __NR_bpf 1
#endif

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
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// CreateMap creates a Map of type mapType, with key size keySize, a value size of
// valueSize and the maximum amount of entries of maxEntries.
// mapType should be one of the bpf_map_type in "uapi/linux/bpf.h"
func CreateMap(mapType int, keySize, valueSize, maxEntries uint32) (int, error) {
	uba := C.union_bpf_attr{}
	C.create_bpf_create_map(
		C.enum_bpf_map_type(mapType),
		C.int(keySize),
		C.int(valueSize),
		C.int(maxEntries),
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_CREATE,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 {
		return int(ret), nil
	}
	return 0, fmt.Errorf("Unable to create map: %s", err)
}

// UpdateElement updates the map in fd with the given value in the given key.
// The flags can have the following values (if you include "uapi/linux/bpf.h"):
// C.BPF_ANY to create new element or update existing;
// C.BPF_NOEXIST to create new element if it didn't exist;
// C.BPF_EXIST to update existing element.
func UpdateElement(fd int, key, value unsafe.Pointer, flags uint64) error {
	uba := C.union_bpf_attr{}
	C.create_bpf_update_elem(
		C.int(fd),
		key,
		value,
		C.ulonglong(flags),
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_UPDATE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to update element: %s", err)
	}

	return nil
}

// LookupElement looks up for the map value stored in fd with the given key. The value
// is stored in the value unsafe.Pointer.
func LookupElement(fd int, key, value unsafe.Pointer) error {
	uba := C.union_bpf_attr{}
	C.create_bpf_lookup_elem(
		C.int(fd),
		key,
		value,
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_LOOKUP_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to lookup element: %s", err)
	}

	return nil
}

// DeleteElement deletes the map element with the given key.
func DeleteElement(fd int, key unsafe.Pointer) error {
	uba := C.union_bpf_attr{}
	C.create_bpf_delete_elem(
		C.int(fd),
		key,
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to delete element: %s", err)
	}

	return nil
}

// GetNextKey stores, in nextKey, the next key after the key of the map in fd.
func GetNextKey(fd int, key, nextKey unsafe.Pointer) error {
	uba := C.union_bpf_attr{}
	C.create_bpf_get_next_key(
		C.int(fd),
		key,
		nextKey,
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_GET_NEXT_KEY,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to get next key: %s", err)
	}

	return nil
}

// ObjPin stores the map's fd in pathname.
func ObjPin(fd int, pathname string) error {
	pathStr := C.CString(pathname)
	uba := C.union_bpf_attr{}
	C.create_bpf_obj_pin(C.int(fd), pathStr, unsafe.Pointer(&uba))
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_OBJ_PIN,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to pin object: %s", err)
	}

	return nil
}

// ObjGet reads the pathname and returns the map's fd read.
func ObjGet(pathname string) (int, error) {
	pathStr := C.CString(pathname)
	uba := C.union_bpf_attr{}
	C.create_bpf_obj_get(pathStr, unsafe.Pointer(&uba))

	fd, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_OBJ_GET,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if fd == 0 || err != 0 {
		return 0, fmt.Errorf("Unable to get object: %s", err)
	}

	return int(fd), nil
}

func OpenOrCreateMap(path string, mapType int, keySize, valueSize, maxEntries uint32) (int, bool, error) {
	var fd int

	isNewMap := false

	rl := syscall.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}

	err := syscall.Setrlimit(C.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return 0, isNewMap, fmt.Errorf("Unable to increase rlimit: %s", err)
	}

	if _, err = os.Stat(path); os.IsNotExist(err) {
		mapDir := filepath.Dir(path)
		if _, err = os.Stat(mapDir); os.IsNotExist(err) {
			if err = os.MkdirAll(mapDir, 0755); err != nil {
				return 0, isNewMap, fmt.Errorf("Unable create map base directory: %s", err)
			}
		}

		fd, err = CreateMap(
			mapType,
			keySize,
			valueSize,
			maxEntries,
		)

		isNewMap = true

		if err != nil {
			return 0, isNewMap, err
		}

		err = ObjPin(fd, path)
		if err != nil {
			return 0, isNewMap, err
		}
	}

	fd, err = ObjGet(path)
	return fd, isNewMap, err
}
