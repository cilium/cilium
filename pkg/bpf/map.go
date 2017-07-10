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

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"sync"
	"unsafe"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// MapType is an enumeration for valid BPF map types
type MapType int

// This enumeration must be in sync with enum bpf_prog_type in <linux/bpf.h>
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
	MapType       MapType
	KeySize       uint32
	ValueSize     uint32
	MaxEntries    uint32
	Flags         uint32
	OwnerProgType ProgType
}

type Map struct {
	MapInfo
	fd   int
	name string
	path string
	once sync.Once
	lock sync.RWMutex

	// NonPersistent is true if the map does not contain persistent data
	// and should be removed on startup.
	NonPersistent bool
}

func NewMap(name string, mapType MapType, keySize int, valueSize int, maxEntries int, flags uint32) *Map {
	return &Map{
		MapInfo: MapInfo{
			MapType:       mapType,
			KeySize:       uint32(keySize),
			ValueSize:     uint32(valueSize),
			MaxEntries:    uint32(maxEntries),
			Flags:         flags,
			OwnerProgType: ProgTypeUnspec,
		},
		name: name,
	}
}

// WithNonPersistent turns the map non-persistent and returns the map
func (m *Map) WithNonPersistent() *Map {
	m.NonPersistent = true
	return m
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
		} else if n, err := fmt.Sscanf(line, "owner_prog_type:\t%d", &value); n == 1 && err == nil {
			info.OwnerProgType = ProgType(value)
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

func (m *Map) migrate(fd int) (bool, error) {
	info, err := GetMapInfo(os.Getpid(), fd)
	if err != nil {
		return false, nil
	}

	mismatch := false

	if info.MapType != m.MapType {
		log.Infof("Map type mismatch for BPF map %s: old: %d new: %d",
			m.path, info.MapType, m.MapType)
		mismatch = true
	}

	if info.KeySize != m.KeySize {
		log.Infof("Key-size mismatch for BPF map %s: old: %d new: %d",
			m.path, info.KeySize, m.KeySize)
		mismatch = true
	}

	if info.ValueSize != m.ValueSize {
		log.Infof("Value-size mismatch for BPF map %s: old: %d new: %d",
			m.path, info.ValueSize, m.ValueSize)
		mismatch = true
	}

	if info.MaxEntries != m.MaxEntries {
		log.Infof("Max entries mismatch for BPF map %s: old: %d new: %d",
			m.path, info.MaxEntries, m.MaxEntries)
		mismatch = true
	}

	if info.Flags != m.Flags {
		log.Infof("Flags mismatch for BPF map %s: old: %d new: %d",
			m.path, info.Flags, m.Flags)
		mismatch = true
	}
	if mismatch {
		b, err := m.containsEntries()
		if err == nil && !b {
			log.Infof("Safely removing empty map %s so it can be recreated", m.path)
			os.Remove(m.path)
			return true, nil
		}

		return false, fmt.Errorf("could not resolve BPF map mismatch (see log for details)")
	}

	return false, nil
}

func (m *Map) OpenOrCreate() (bool, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.fd != 0 {
		return false, nil
	}

	if err := m.setPathIfUnset(); err != nil {
		return false, err
	}

	// If the map represents non-persistent data, always remove the map
	// before opening or creating.
	if m.NonPersistent {
		os.Remove(m.path)
	}

reopen:
	fd, isNew, err := OpenOrCreateMap(m.path, int(m.MapType), m.KeySize, m.ValueSize, m.MaxEntries, m.Flags)
	if err != nil {
		return false, err
	}

	// Only persistent maps need to be migrated, non-persistent maps will
	// have been deleted above before opening.
	if !m.NonPersistent {
		if retry, err := m.migrate(fd); err != nil {
			if isNew {
				os.Remove(m.path)
			}
			return false, err
		} else if retry {
			goto reopen
		}
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
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.fd != 0 {
		unix.Close(m.fd)
		m.fd = 0
	}

	return nil
}

type DumpParser func(key []byte, value []byte) (MapKey, MapValue, error)
type DumpCallback func(key MapKey, value MapValue)

func (m *Map) Dump(parser DumpParser, cb DumpCallback) error {
	m.lock.RLock()
	defer m.lock.RUnlock()

	key := make([]byte, m.KeySize)
	nextKey := make([]byte, m.KeySize)
	value := make([]byte, m.ValueSize)

	if err := m.Open(); err != nil {
		return err
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

// containsEntries returns true if the map contains at least one entry
// must hold map mutex
func (m *Map) containsEntries() (bool, error) {
	key := make([]byte, m.KeySize)
	nextKey := make([]byte, m.KeySize)
	value := make([]byte, m.ValueSize)

	err := GetNextKey(
		m.fd,
		unsafe.Pointer(&key[0]),
		unsafe.Pointer(&nextKey[0]),
	)

	if err != nil {
		return false, nil
	}

	err = LookupElement(
		m.fd,
		unsafe.Pointer(&nextKey[0]),
		unsafe.Pointer(&value[0]),
	)

	if err != nil {
		return false, err
	}

	return true, nil
}

func (m *Map) Lookup(key MapKey) (MapValue, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	value := key.NewValue()

	if err := m.Open(); err != nil {
		return nil, err
	}

	err := LookupElement(m.fd, key.GetKeyPtr(), value.GetValuePtr())
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (m *Map) Update(key MapKey, value MapValue) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if err := m.Open(); err != nil {
		return err
	}

	return UpdateElement(m.fd, key.GetKeyPtr(), value.GetValuePtr(), 0)
}

func (m *Map) Delete(key MapKey) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if err := m.Open(); err != nil {
		return err
	}

	return DeleteElement(m.fd, key.GetKeyPtr())
}

// DeleteAll deletes all entries of a map by traversing the map and deleting individual
// entries. Note that if entries are added while the taversal is in progress,
// such entries may survive the deletion process.
func (m *Map) DeleteAll() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	key := make([]byte, m.KeySize)
	nextKey := make([]byte, m.KeySize)

	if err := m.Open(); err != nil {
		return err
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

//GetNextKey returns the next key in the Map after key.
func (m *Map) GetNextKey(key MapKey, nextKey MapKey) error {
	if err := m.Open(); err != nil {
		return err
	}

	return GetNextKey(m.fd, key.GetKeyPtr(), nextKey.GetKeyPtr())
}
