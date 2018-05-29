// Copyright 2016-2018 Authors of Cilium
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
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
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
	fmt.Stringer

	// Returns pointer to start of key
	GetKeyPtr() unsafe.Pointer

	// Allocates a new value matching the key type
	NewValue() MapValue
}

type MapValue interface {
	fmt.Stringer

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
	lock lock.RWMutex

	// openLock serializes calls to Map.Open()
	openLock lock.Mutex

	// NonPersistent is true if the map does not contain persistent data
	// and should be removed on startup.
	NonPersistent bool

	// DumpParser is a function for parsing keys and values from BPF maps
	dumpParser DumpParser
}

// NewMap creates a new Map instance - object representing a BPF map
func NewMap(name string, mapType MapType, keySize int, valueSize int, maxEntries int, flags uint32, dumpParser DumpParser) *Map {
	m := &Map{
		MapInfo: MapInfo{
			MapType:       mapType,
			KeySize:       uint32(keySize),
			ValueSize:     uint32(valueSize),
			MaxEntries:    uint32(maxEntries),
			Flags:         flags,
			OwnerProgType: ProgTypeUnspec,
		},
		name:       path.Base(name),
		dumpParser: dumpParser,
	}
	m.setPathIfUnset()
	return m
}

// WithNonPersistent turns the map non-persistent and returns the map
func (m *Map) WithNonPersistent() *Map {
	m.NonPersistent = true
	return m
}

func (m *Map) GetFd() int {
	return m.fd
}

// DeepEquals compares the current map against another map to see that the
// attributes of the two maps are the same.
func (m *Map) DeepEquals(other *Map) bool {
	return m.MapInfo == other.MapInfo &&
		m.name == other.name &&
		m.path == other.path &&
		m.NonPersistent == other.NonPersistent
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

retry:
	fd, isNew, err := OpenOrCreateMap(m.path, int(m.MapType), m.KeySize, m.ValueSize, m.MaxEntries, m.Flags)
	if err != nil && m.MapType == BPF_MAP_TYPE_LPM_TRIE {
		// If the map type is an LPM, then we can typically fall back
		// to a hash map. Note that this requires datapath support,
		// such as an unrolled loop performing repeated lookups with
		// a defined set of prefixes.
		log.WithError(err).Debugf("Kernel does not support LPM maps, creating hash table for %s instead.", m.name)
		m.MapType = BPF_MAP_TYPE_HASH
		goto retry
	}
	if err != nil {
		return false, err
	}

	m.fd = fd
	return isNew, nil
}

func (m *Map) Open() error {
	m.openLock.Lock()
	defer m.openLock.Unlock()

	if m.fd != 0 {
		return nil
	}

	if err := m.setPathIfUnset(); err != nil {
		return err
	}

	fd, err := ObjGet(m.path)
	if err != nil {
		return err
	}

	m.fd = fd
	return nil
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
type MapValidator func(path string) (bool, error)

// DumpWithCallback iterates over the Map and calls the given callback
// function on each iteration. That callback function is receiving the
// actual key and value.
func (m *Map) DumpWithCallback(cb DumpCallback) error {
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

		k, v, err := m.dumpParser(nextKey, value)
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

// Dump returns the map (type map[string][]string) which contains all
// data stored in BPF map.
func (m *Map) Dump(hash map[string][]string) error {
	callback := func(key MapKey, value MapValue) {
		hash[key.String()] = append(hash[key.String()], value.String())
	}

	if err := m.DumpWithCallback(callback); err != nil {
		return err
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

	scopedLog := log.WithFields(logrus.Fields{logfields.Path: m.path, "name": m.name})
	scopedLog.Debug("deleting all entries in map")

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

// ConvertKeyValue converts key and value from bytes to given Golang struct pointers.
func ConvertKeyValue(bKey []byte, bValue []byte, key interface{}, value interface{}) error {
	keyBuf := bytes.NewBuffer(bKey)
	valueBuf := bytes.NewBuffer(bValue)

	if err := binary.Read(keyBuf, byteorder.Native, key); err != nil {
		return fmt.Errorf("Unable to convert key: %s", err)
	}

	if err := binary.Read(valueBuf, byteorder.Native, value); err != nil {
		return fmt.Errorf("Unable to convert value: %s", err)
	}

	return nil
}

// MetadataDiff compares the metadata of the BPF maps and returns false if the
// metadata does not match
func (m *Map) MetadataDiff(other *Map) bool {
	if m == nil || other == nil {
		return false
	}

	// create copies
	m1 := *m
	m2 := *other

	// ignore fd in diff
	m1.fd = 0
	m2.fd = 0

	logging.MultiLine(log.Debug, comparator.Compare(m1, m2))

	return m1.DeepEquals(&m2)
}
