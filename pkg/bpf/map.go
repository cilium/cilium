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
	"time"
	"unsafe"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/controller"
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

	// maxSyncErrors is the maximum consecutive errors syncing before the
	// controller bails out
	maxSyncErrors = 512

	// errorResolverSchedulerMinInterval is the minimum interval for the
	// error resolver to be scheduled. This minimum interval ensures not to
	// overschedule if a large number of updates fail in a row.
	errorResolverSchedulerMinInterval = 5 * time.Second

	// errorResolverSchedulerDelay is the delay to update the controller
	// after determination that a run is needed. The delay allows to
	// schedule the resolver after series of updates have failed.
	errorResolverSchedulerDelay = 200 * time.Millisecond
)

var (
	mapControllers = controller.NewManager()
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

// DesiredAction is the action to be performed on the BPF map
type DesiredAction int

const (
	// OK indicates that to further action is required and the entry is in
	// sync
	OK DesiredAction = iota

	// Insert indicates that the entry needs to be created or updated
	Insert

	// Delete indicates that the entry needs to be deleted
	Delete
)

func (d DesiredAction) String() string {
	switch d {
	case OK:
		return "sync"
	case Insert:
		return "to-be-inserted"
	case Delete:
		return "to-be-deleted"
	default:
		return "unknown"
	}
}

type cacheEntry struct {
	Key   MapKey
	Value MapValue

	DesiredAction DesiredAction
	LastError     error
}

type Map struct {
	MapInfo
	fd   int
	name string
	path string
	once sync.Once
	lock lock.RWMutex

	// enableSync is true when synchronization retries have been enabled.
	enableSync bool

	// openLock serializes calls to Map.Open()
	openLock lock.Mutex

	// NonPersistent is true if the map does not contain persistent data
	// and should be removed on startup.
	NonPersistent bool

	// DumpParser is a function for parsing keys and values from BPF maps
	dumpParser DumpParser

	cache map[string]*cacheEntry

	// errorResolverLastScheduled is the timestamp when the error resolver
	// was last scheduled
	errorResolverLastScheduled time.Time

	// outstandingErrors is the number of outsanding errors syncing with
	// the kernel
	outstandingErrors int
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
	return m
}

// WithNonPersistent turns the map non-persistent and returns the map
func (m *Map) WithNonPersistent() *Map {
	m.NonPersistent = true
	return m
}

// scheduleErrorResolver schedules a periodic resolver controller that scans
// all BPF map caches for unresolved errors and attempts to resolve them. On
// error of resolution, the controller is-rescheduled in an expedited manner
// with an exponential back-off.
//
// m.lock must be held for writing
func (m *Map) scheduleErrorResolver() {
	m.outstandingErrors++

	if time.Since(m.errorResolverLastScheduled) <= errorResolverSchedulerMinInterval {
		return
	}

	m.errorResolverLastScheduled = time.Now()

	go func() {
		time.Sleep(errorResolverSchedulerDelay)
		mapControllers.UpdateController(m.controllerName(),
			controller.ControllerParams{
				DoFunc:      m.resolveErrors,
				RunInterval: errorResolverSchedulerMinInterval,
			},
		)
	}()

}

// WithCache enables use of a cache. This will store all entries inserted from
// user space in a local cache (map) and will indicate the status of each
// individual entry.
func (m *Map) WithCache() *Map {
	m.cache = map[string]*cacheEntry{}
	m.enableSync = true
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

func (m *Map) controllerName() string {
	return fmt.Sprintf("bpf-map-sync-%s", m.name)
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

	m := &Map{
		MapInfo: *info,
		fd:      fd,
		name:    path.Base(name),
		path:    name,
	}

	registerMap(name, m)

	return m, nil
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

	registerMap(m.path, m)

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

	registerMap(m.path, m)

	m.fd = fd
	return nil
}

func (m *Map) Close() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.enableSync {
		mapControllers.RemoveController(m.controllerName())
	}

	if m.fd != 0 {
		unix.Close(m.fd)
		m.fd = 0
	}

	unregisterMap(m.path, m)

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
	var err error

	m.lock.Lock()
	defer m.lock.Unlock()

	defer func() {
		if m.cache == nil {
			return
		}

		desiredAction := OK
		if err != nil {
			desiredAction = Insert
			m.scheduleErrorResolver()
		}

		m.cache[key.String()] = &cacheEntry{
			Key:           key,
			Value:         value,
			DesiredAction: desiredAction,
			LastError:     err,
		}
	}()

	if err = m.Open(); err != nil {
		return err
	}

	err = UpdateElement(m.fd, key.GetKeyPtr(), value.GetValuePtr(), 0)
	return err
}

// deleteCacheEntry evaluates the specified error, if nil the map key is
// removed from the cache to indicate successful deletion. If non-nil, the map
// key entry in the cache is updated to indicate deletion failure with the
// specified error.
//
// Caller must hold m.lock for writing
func (m *Map) deleteCacheEntry(key MapKey, err error) {
	if m.cache == nil {
		return
	}

	k := key.String()
	if err == nil {
		delete(m.cache, k)
	} else {
		entry, ok := m.cache[k]
		if !ok {
			m.cache[k] = &cacheEntry{
				Key: key,
			}
			entry = m.cache[k]
		}

		entry.DesiredAction = Delete
		entry.LastError = err
		m.scheduleErrorResolver()
	}
}

func (m *Map) Delete(key MapKey) error {
	var err error

	m.lock.Lock()
	defer m.lock.Unlock()

	defer m.deleteCacheEntry(key, err)

	if err = m.Open(); err != nil {
		return err
	}

	err = DeleteElement(m.fd, key.GetKeyPtr())
	return err
}

// scopedLogger returns a logger scoped for the map. m.lock must be held.
func (m *Map) scopedLogger() *logrus.Entry {
	return log.WithFields(logrus.Fields{logfields.Path: m.path, "name": m.name})
}

// DeleteAll deletes all entries of a map by traversing the map and deleting individual
// entries. Note that if entries are added while the taversal is in progress,
// such entries may survive the deletion process.
func (m *Map) DeleteAll() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	scopedLog := m.scopedLogger()
	scopedLog.Debug("deleting all entries in map")

	key := make([]byte, m.KeySize)
	nextKey := make([]byte, m.KeySize)

	if m.cache != nil {
		// Mark all entries for deletion, upon successful deletion,
		// entries will be removed or the LastError will be updated
		for _, entry := range m.cache {
			entry.DesiredAction = Delete
			entry.LastError = fmt.Errorf("deletion pending")
		}
	}

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

		k, _, err2 := m.dumpParser(nextKey, []byte{})
		if err2 == nil {
			m.deleteCacheEntry(k, err)
		} else {
			log.WithError(err2).Warning("Unable to correlate iteration key %v with cache entry. Inconsistent cache.", nextKey)
		}

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

	if len(bKey) > 0 {
		if err := binary.Read(keyBuf, byteorder.Native, key); err != nil {
			return fmt.Errorf("Unable to convert key: %s", err)
		}
	}

	if len(bValue) > 0 {
		if err := binary.Read(valueBuf, byteorder.Native, value); err != nil {
			return fmt.Errorf("Unable to convert value: %s", err)
		}
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

// GetModel returns a BPF map in the representation served via the API
func (m *Map) GetModel() *models.BPFMap {
	m.lock.RLock()
	defer m.lock.RUnlock()

	mapModel := &models.BPFMap{
		Path: m.path,
	}

	if m.cache != nil {
		mapModel.Cache = make([]*models.BPFMapEntry, len(m.cache))
		i := 0
		for k, entry := range m.cache {
			model := &models.BPFMapEntry{
				Key:           k,
				DesiredAction: entry.DesiredAction.String(),
			}

			if entry.LastError != nil {
				model.LastError = entry.LastError.Error()
			}

			if entry.Value != nil {
				model.Value = entry.Value.String()
			}
			mapModel.Cache[i] = model
			i++
		}
	}

	return mapModel
}

// resolveErrors is schedule by scheduleErrorResolver() and runs periodically.
// It resolves up to maxSyncErrors discrepancies between cache and BPF map in
// the kernel.
func (m *Map) resolveErrors() error {
	started := time.Now()

	m.lock.Lock()
	defer m.lock.Unlock()

	if m.cache == nil {
		return nil
	}

	if m.outstandingErrors == 0 {
		return nil
	}

	scopedLogger := m.scopedLogger()
	scopedLogger.WithField("remaining", m.outstandingErrors).
		Debug("Starting periodic BPF map error resolver")

	resolved := 0
	scanned := 0
	errors := 0
	for k, e := range m.cache {
		scanned++

		switch e.DesiredAction {
		case OK:
		case Insert:
			err := UpdateElement(m.fd, e.Key.GetKeyPtr(), e.Value.GetValuePtr(), 0)
			if err == nil {
				e.DesiredAction = OK
				e.LastError = nil
				resolved++
				m.outstandingErrors--
			} else {
				e.LastError = err
				errors++
			}

		case Delete:
			_, err := deleteElement(m.fd, e.Key.GetKeyPtr())
			if err == 0 || err == unix.ENOENT {
				delete(m.cache, k)
				resolved++
				m.outstandingErrors--
			} else {
				e.LastError = err
				errors++
			}
		}

		m.cache[k] = e

		// bail out if maximum errors are reached to relax the map lock
		if errors > maxSyncErrors {
			break
		}
	}

	scopedLogger.WithFields(logrus.Fields{
		"remaining": m.outstandingErrors,
		"resolved":  resolved,
		"scanned":   scanned,
		"duration":  time.Since(started),
	}).Debug("BPF map error resolver completed")

	if m.outstandingErrors > 0 {
		return fmt.Errorf("%d map sync errors", m.outstandingErrors)
	}

	return nil
}
