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
*/

import "C"

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"sync"
	"syscall"
	"unsafe"
)

type MapType int

// This enumeration must be in sync with <linux/bpf.h>
const (
	MapTypeUnspec MapType = iota
	MapTypeHash
	MapTypeArray
	MapTypeProgArray
	MapTypePerfEventArray
	MapTypePerCPUHash
	MapTypePerCPUArray
	MapTypeStackTrace
	MapTypeCgroupArray
	MapTypeLRUHash
	MapTypeLRUPerCPUHash
	MapTypeLPMTrie
	MapTypeArrayOfMaps
	MapTypeHashOfMaps
)

func (t MapType) String() string {
	switch t {
	case MapTypeHash:
		return "Hash"
	case MapTypeArray:
		return "Array"
	case MapTypeProgArray:
		return "Program array"
	case MapTypePerfEventArray:
		return "Event array"
	case MapTypePerCPUHash:
		return "Per-CPU hash"
	case MapTypePerCPUArray:
		return "Per-CPU array"
	case MapTypeStackTrace:
		return "Stack trace"
	case MapTypeCgroupArray:
		return "Cgroup array"
	case MapTypeLRUHash:
		return "LRU hash"
	case MapTypeLRUPerCPUHash:
		return "LRU per-CPU hash"
	case MapTypeLPMTrie:
		return "Longest prefix match trie"
	case MapTypeArrayOfMaps:
		return "Array of maps"
	case MapTypeHashOfMaps:
		return "Hash of maps"
	}

	return "Unknown"
}

type MapKey interface {
	// Returns pointer to start of key
	GetKeyPtr() unsafe.Pointer

	// Allocates a new value matching the key type
	NewValue() MapValue
}

type MapValue interface {
	// Returns pointer to start of value
	GetValuePtr() unsafe.Pointer
}

type MapInfo struct {
	MapType    MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

type Map struct {
	MapInfo
	fd   int
	name string
	path string
	once sync.Once
}

func NewMap(name string, mapType MapType, keySize int, valueSize int, maxEntries int) *Map {
	return &Map{
		MapInfo: MapInfo{
			MapType:    mapType,
			KeySize:    uint32(keySize),
			ValueSize:  uint32(valueSize),
			MaxEntries: uint32(maxEntries),
		},
		name: name,
	}
}

func (m *Map) GetFd() int {
	return m.fd
}

func GetMapInfo(pid int, fd int) (*MapInfo, error) {
	fdinfoFile := fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd)

	file, err := os.Open(fdinfoFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info := &MapInfo{}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		var value int

		line := scanner.Text()
		if n, err := fmt.Sscanf(line, "map_type:\t%d", &value); n == 1 && err == nil {
			info.MapType = MapType(value)
		} else if n, err := fmt.Sscanf(line, "key_size:\t%d", &value); n == 1 && err == nil {
			info.KeySize = uint32(value)
		} else if n, err := fmt.Sscanf(line, "value_size:\t%d", &value); n == 1 && err == nil {
			info.ValueSize = uint32(value)
		} else if n, err := fmt.Sscanf(line, "max_entries:\t%d", &value); n == 1 && err == nil {
			info.MaxEntries = uint32(value)
		} else if n, err := fmt.Sscanf(line, "map_flags:\t%x", &value); n == 1 && err == nil {
			info.Flags = uint32(value)
		}
	}

	if scanner.Err() != nil {
		return nil, scanner.Err()
	}

	return info, nil
}

func OpenMap(name string) (*Map, error) {
	// Expand path if needed
	if !path.IsAbs(name) {
		name = MapPath(name)
	}

	fd, err := ObjGet(name)
	if err != nil {
		return nil, err
	}

	info, err := GetMapInfo(os.Getpid(), fd)
	if err != nil {
		return nil, err
	}

	if info.MapType == 0 {
		return nil, fmt.Errorf("Unable to determine map type")
	}

	if info.KeySize == 0 {
		return nil, fmt.Errorf("Unable to determine map key size")
	}

	return &Map{
		MapInfo: *info,
		fd:      fd,
		name:    path.Base(name),
		path:    name,
	}, nil
}

func (m *Map) setPathIfUnset() error {
	if m.path == "" {
		if m.name == "" {
			return fmt.Errorf("either path or name must be set")
		}

		m.path = MapPath(m.name)
	}

	return nil
}

func (m *Map) OpenOrCreate() (bool, error) {
	if m.fd != 0 {
		return false, nil
	}

	if err := m.setPathIfUnset(); err != nil {
		return false, err
	}

	fd, isNew, err := OpenOrCreateMap(m.path, int(m.MapType), m.KeySize, m.ValueSize, m.MaxEntries)
	if err != nil {
		return false, err
	}

	m.fd = fd

	return isNew, nil
}

func (m *Map) Open() error {
	var err error
	m.once.Do(func() {
		if m.fd != 0 {
			err = nil
			return
		}

		if err = m.setPathIfUnset(); err != nil {
			return
		}
		var fd int
		fd, err = ObjGet(m.path)
		if err != nil {
			return
		}

		m.fd = fd
	})
	return err
}

func (m *Map) Close() error {
	if m.fd != 0 {
		syscall.Close(m.fd)
		m.fd = 0
	}

	return nil
}

type DumpParser func(key []byte, value []byte) (MapKey, MapValue, error)
type DumpCallback func(key MapKey, value MapValue)

func (m *Map) Dump(parser DumpParser, cb DumpCallback) error {
	key := make([]byte, m.KeySize)
	nextKey := make([]byte, m.KeySize)
	value := make([]byte, m.ValueSize)

	if m.fd == 0 {
		if err := m.Open(); err != nil {
			return err
		}
	}

	for {
		err := GetNextKey(
			m.fd,
			unsafe.Pointer(&key[0]),
			unsafe.Pointer(&nextKey[0]),
		)

		if err != nil {
			break
		}

		err = LookupElement(
			m.fd,
			unsafe.Pointer(&nextKey[0]),
			unsafe.Pointer(&value[0]),
		)

		if err != nil {
			return err
		}

		k, v, err := parser(nextKey, value)
		if err != nil {
			return err
		}

		if cb != nil {
			cb(k, v)
		}

		copy(key, nextKey)
	}

	return nil
}

func (m *Map) Lookup(key MapKey) (MapValue, error) {
	value := key.NewValue()

	if m.fd == 0 {
		if err := m.Open(); err != nil {
			return nil, err
		}
	}

	err := LookupElement(m.fd, key.GetKeyPtr(), value.GetValuePtr())
	if err != nil {
		return nil, err
	}

	return value, nil
}

func (m *Map) Update(key MapKey, value MapValue) error {
	if m.fd == 0 {
		if err := m.Open(); err != nil {
			return err
		}
	}

	return UpdateElement(m.fd, key.GetKeyPtr(), value.GetValuePtr(), 0)
}

func (m *Map) Delete(key MapKey) error {
	if m.fd == 0 {
		if err := m.Open(); err != nil {
			return err
		}
	}

	return DeleteElement(m.fd, key.GetKeyPtr())
}

// DeleteAll deletes all entries of a map by traversing the map and deleting individual
// entries. Note that if entries are added while the taversal is in progress,
// such entries may survive the deletion process.
func (m *Map) DeleteAll() error {
	key := make([]byte, m.KeySize)
	nextKey := make([]byte, m.KeySize)

	if m.fd == 0 {
		if err := m.Open(); err != nil {
			return err
		}
	}

	for {
		err := GetNextKey(
			m.fd,
			unsafe.Pointer(&key[0]),
			unsafe.Pointer(&nextKey[0]),
		)

		if err != nil {
			break
		}

		err = DeleteElement(m.fd, unsafe.Pointer(&nextKey[0]))
		if err != nil {
			return err
		}

		copy(key, nextKey)
	}

	return nil
}
