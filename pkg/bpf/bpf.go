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

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bpf")

const (
	// BPF map type constants. Must match enum bpf_map_type from linux/bpf.h
	BPF_MAP_TYPE_UNSPEC              = 0
	BPF_MAP_TYPE_HASH                = 1
	BPF_MAP_TYPE_ARRAY               = 2
	BPF_MAP_TYPE_PROG_ARRAY          = 3
	BPF_MAP_TYPE_PERF_EVENT_ARRAY    = 4
	BPF_MAP_TYPE_PERCPU_HASH         = 5
	BPF_MAP_TYPE_PERCPU_ARRAY        = 6
	BPF_MAP_TYPE_STACK_TRACE         = 7
	BPF_MAP_TYPE_CGROUP_ARRAY        = 8
	BPF_MAP_TYPE_LRU_HASH            = 9
	BPF_MAP_TYPE_LRU_PERCPU_HASH     = 10
	BPF_MAP_TYPE_LPM_TRIE            = 11
	BPF_MAP_TYPE_ARRAY_OF_MAPS       = 12
	BPF_MAP_TYPE_HASH_OF_MAPS        = 13
	BPF_MAP_TYPE_DEVMAP              = 14
	BPF_MAP_TYPE_SOCKMAP             = 15
	BPF_MAP_TYPE_CPUMAP              = 16
	BPF_MAP_TYPE_XSKMAP              = 17
	BPF_MAP_TYPE_SOCKHASH            = 18
	BPF_MAP_TYPE_CGROUP_STORAGE      = 19
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20

	// BPF syscall command constants. Must match enum bpf_cmd from linux/bpf.h
	BPF_MAP_CREATE          = 0
	BPF_MAP_LOOKUP_ELEM     = 1
	BPF_MAP_UPDATE_ELEM     = 2
	BPF_MAP_DELETE_ELEM     = 3
	BPF_MAP_GET_NEXT_KEY    = 4
	BPF_PROG_LOAD           = 5
	BPF_OBJ_PIN             = 6
	BPF_OBJ_GET             = 7
	BPF_PROG_ATTACH         = 8
	BPF_PROG_DETACH         = 9
	BPF_PROG_TEST_RUN       = 10
	BPF_PROG_GET_NEXT_ID    = 11
	BPF_MAP_GET_NEXT_ID     = 12
	BPF_PROG_GET_FD_BY_ID   = 13
	BPF_MAP_GET_FD_BY_ID    = 14
	BPF_OBJ_GET_INFO_BY_FD  = 15
	BPF_PROG_QUERY          = 16
	BPF_RAW_TRACEPOINT_OPEN = 17
	BPF_BTF_LOAD            = 18
	BPF_BTF_GET_FD_BY_ID    = 19
	BPF_TASK_FD_QUERY       = 20

	// Flags for BPF_MAP_UPDATE_ELEM. Must match values from linux/bpf.h
	BPF_ANY     = 0
	BPF_NOEXIST = 1
	BPF_EXIST   = 2

	// Flags for BPF_MAP_CREATE. Must match values from linux/bpf.h
	BPF_F_NO_PREALLOC   = 1 << 0
	BPF_F_NO_COMMON_LRU = 1 << 1
	BPF_F_NUMA_NODE     = 1 << 2

	// Flags for BPF_PROG_QUERY
	BPF_F_QUERY_EFFECTVE = 1 << 0

	// Flags for accessing BPF object
	BPF_F_RDONLY = 1 << 3
	BPF_F_WRONLY = 1 << 4

	// Flag for stack_map, store build_id+offset instead of pointer
	BPF_F_STACK_BUILD_ID = 1 << 5
)

// CreateMap creates a Map of type mapType, with key size keySize, a value size of
// valueSize and the maximum amount of entries of maxEntries.
// mapType should be one of the bpf_map_type in "uapi/linux/bpf.h"
// When mapType is the type HASH_OF_MAPS an innerID is required to point at a
// map fd which has the same type/keySize/valueSize/maxEntries as expected map
// entries. For all other mapTypes innerID is ignored and should be zeroed.
func CreateMap(mapType int, keySize, valueSize, maxEntries, flags, innerID uint32) (int, error) {
	// This struct must be in sync with union bpf_attr's anonymous struct
	// used by the BPF_MAP_CREATE command
	uba := struct {
		mapType    uint32
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
		mapFlags   uint32
		innerID    uint32
	}{
		uint32(mapType),
		keySize,
		valueSize,
		maxEntries,
		flags,
		innerID,
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_CREATE,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if err != 0 {
		return 0, fmt.Errorf("Unable to create map: %s", err)
	}
	return int(ret), nil
}

// This struct must be in sync with union bpf_attr's anonymous struct used by
// BPF_MAP_*_ELEM commands
type bpfAttrMapOpElem struct {
	mapFd uint32
	pad0  [4]byte
	key   uint64
	value uint64 // union: value or next_key
	flags uint64
}

// UpdateElement updates the map in fd with the given value in the given key.
// The flags can have the following values:
// bpf.BPF_ANY to create new element or update existing;
// bpf.BPF_NOEXIST to create new element if it didn't exist;
// bpf.BPF_EXIST to update existing element.
func UpdateElement(fd int, key, value unsafe.Pointer, flags uint64) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
		flags: uint64(flags),
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_UPDATE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to update element for map with file descriptor %d: %s", fd, err)
	}

	return nil
}

// LookupElement looks up for the map value stored in fd with the given key. The value
// is stored in the value unsafe.Pointer.
func LookupElement(fd int, key, value unsafe.Pointer) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_LOOKUP_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to lookup element in map with file descriptor %d: %s", fd, err)
	}

	return nil
}

func deleteElement(fd int, key unsafe.Pointer) (uintptr, syscall.Errno) {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
	}
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	return ret, err
}

// DeleteElement deletes the map element with the given key.
func DeleteElement(fd int, key unsafe.Pointer) error {
	ret, err := deleteElement(fd, key)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to delete element from map with file descriptor %d: %s", fd, err)
	}

	return nil
}

// GetNextKey stores, in nextKey, the next key after the key of the map in fd.
func GetNextKey(fd int, key, nextKey unsafe.Pointer) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(nextKey)),
	}
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_GET_NEXT_KEY,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to get next key from map with file descriptor %d: %s", fd, err)
	}

	return nil
}

// This struct must be in sync with union bpf_attr's anonymous struct used by
// BPF_OBJ_*_ commands
type bpfAttrObjOp struct {
	pathname uint64
	fd       uint32
	pad0     [4]byte
}

// ObjPin stores the map's fd in pathname.
func ObjPin(fd int, pathname string) error {
	pathStr := C.CString(pathname)
	defer C.free(unsafe.Pointer(pathStr))
	uba := bpfAttrObjOp{
		pathname: uint64(uintptr(unsafe.Pointer(pathStr))),
		fd:       uint32(fd),
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_OBJ_PIN,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to pin object with file descriptor %d to %s: %s", fd, pathname, err)
	}

	return nil
}

// ObjGet reads the pathname and returns the map's fd read.
func ObjGet(pathname string) (int, error) {
	pathStr := C.CString(pathname)
	defer C.free(unsafe.Pointer(pathStr))
	uba := bpfAttrObjOp{
		pathname: uint64(uintptr(unsafe.Pointer(pathStr))),
	}

	fd, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_OBJ_GET,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if fd == 0 || err != 0 {
		return 0, fmt.Errorf("Unable to get object %s: %s", pathname, err)
	}

	return int(fd), nil
}

type bpfAttrFdFromId struct {
	ID     uint32
	NextID uint32
	Flags  uint32
}

// MapFdFromID retrieves a file descriptor based on a map ID.
func MapFdFromID(id int) (int, error) {
	uba := bpfAttrFdFromId{
		ID: uint32(id),
	}

	fd, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_GET_FD_BY_ID,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if fd == 0 || err != 0 {
		return 0, fmt.Errorf("Unable to get object fd from id %d: %s", id, err)
	}

	return int(fd), nil
}

// ObjClose closes the map's fd.
func ObjClose(fd int) error {
	if fd > 0 {
		return unix.Close(fd)
	}
	return nil
}

func objCheck(fd int, path string, mapType int, keySize, valueSize, maxEntries, flags uint32) bool {
	info, err := GetMapInfo(os.Getpid(), fd)
	if err != nil {
		return false
	}

	scopedLog := log.WithField(logfields.Path, path)
	mismatch := false

	if int(info.MapType) != mapType {
		scopedLog.WithFields(logrus.Fields{
			"old": info.MapType,
			"new": MapType(mapType),
		}).Info("Map type mismatch for BPF map")
		mismatch = true
	}

	if info.KeySize != keySize {
		scopedLog.WithFields(logrus.Fields{
			"old": info.KeySize,
			"new": keySize,
		}).Info("Key-size mismatch for BPF map")
		mismatch = true
	}

	if info.ValueSize != valueSize {
		scopedLog.WithFields(logrus.Fields{
			"old": info.ValueSize,
			"new": valueSize,
		}).Info("Value-size mismatch for BPF map")
		mismatch = true
	}

	if info.MaxEntries != maxEntries {
		scopedLog.WithFields(logrus.Fields{
			"old": info.MaxEntries,
			"new": maxEntries,
		}).Info("Max entries mismatch for BPF map")
		mismatch = true
	}
	if info.Flags != flags {
		scopedLog.WithFields(logrus.Fields{
			"old": info.Flags,
			"new": flags,
		}).Info("Flags mismatch for BPF map")
		mismatch = true
	}

	if mismatch {
		if info.MapType == MapTypeProgArray {
			return false
		}

		scopedLog.Info("Removing map to allow for property upgrade (expect map data loss)")

		// Kernel still holds map reference count via attached prog.
		// Only exception is prog array, but that is already resolved
		// differently.
		os.Remove(path)
		return true
	}

	return false
}

func OpenOrCreateMap(path string, mapType int, keySize, valueSize, maxEntries, flags uint32, innerID uint32) (int, bool, error) {
	var fd int

	redo := false
	isNewMap := false

	rl := unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}

	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		if os.IsPermission(err) {
			log.Error("Unable to set RLimits, insufficient permissions")
		}
		return 0, isNewMap, fmt.Errorf("Unable to increase rlimit: %s", err)
	}

recreate:
	if _, err = os.Stat(path); os.IsNotExist(err) || redo {
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
			flags,
			innerID,
		)

		defer func() {
			if err != nil {
				// In case of error, we need to close
				// this fd since it was open by CreateMap
				ObjClose(fd)
			}
		}()

		isNewMap = true

		if err != nil {
			return 0, isNewMap, err
		}

		err = ObjPin(fd, path)
		if err != nil {
			return 0, isNewMap, err
		}

		return fd, isNewMap, nil
	}

	fd, err = ObjGet(path)
	if err == nil {
		redo = objCheck(
			fd,
			path,
			mapType,
			keySize,
			valueSize,
			maxEntries,
			flags,
		)
		if redo == true {
			ObjClose(fd)
			goto recreate
		}
	}

	return fd, isNewMap, err
}

// GetMtime returns monotonic time that can be used to compare
// values with ktime_get_ns() BPF helper, e.g. needed to check
// the timeout in sec for BPF entries. We return the raw nsec,
// although that is not quite usable for comparison. Go has
// runtime.nanotime() but doesn't expose it as API.
func GetMtime() (uint64, error) {
	var ts unix.Timespec

	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return 0, fmt.Errorf("Unable get time: %s", err)
	}

	return uint64(unix.TimespecToNsec(ts)), nil
}
