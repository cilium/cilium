// Copyright 2016-2020 Authors of Cilium
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

// +build linux

package bpf

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"time"
	"unsafe"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf/binary"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// ErrMaxLookup is returned when the maximum number of map element lookups has
// been reached.
var ErrMaxLookup = errors.New("maximum number of lookups reached")

type MapKey interface {
	fmt.Stringer

	// Returns pointer to start of key
	GetKeyPtr() unsafe.Pointer

	// Allocates a new value matching the key type
	NewValue() MapValue

	// DeepCopyMapKey returns a deep copy of the map key
	DeepCopyMapKey() MapKey
}

type MapValue interface {
	fmt.Stringer

	// Returns pointer to start of value
	GetValuePtr() unsafe.Pointer

	// DeepCopyMapValue returns a deep copy of the map value
	DeepCopyMapValue() MapValue
}

type MapInfo struct {
	MapType  MapType
	MapKey   MapKey
	KeySize  uint32
	MapValue MapValue
	// ReadValueSize is the value size that is used to read from the BPF maps
	// this value an the ValueSize values can be different for BPF_MAP_TYPE_PERCPU_HASH
	// for example.
	ReadValueSize uint32
	ValueSize     uint32
	MaxEntries    uint32
	Flags         uint32
	InnerID       uint32
	OwnerProgType ProgType
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
	lock lock.RWMutex

	// inParallelMode is true when the Map is currently being run in
	// parallel and all modifications are performed on both maps until
	// EndParallelMode() is called.
	inParallelMode bool

	// cachedCommonName is the common portion of the name excluding any
	// endpoint ID
	cachedCommonName string

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
func NewMap(name string, mapType MapType, mapKey MapKey, keySize int, mapValue MapValue, valueSize, maxEntries int, flags uint32, innerID uint32, dumpParser DumpParser) *Map {
	m := &Map{
		MapInfo: MapInfo{
			MapType:       mapType,
			MapKey:        mapKey,
			KeySize:       uint32(keySize),
			MapValue:      mapValue,
			ReadValueSize: uint32(valueSize),
			ValueSize:     uint32(valueSize),
			MaxEntries:    uint32(maxEntries),
			Flags:         flags,
			InnerID:       innerID,
			OwnerProgType: ProgTypeUnspec,
		},
		name:       path.Base(name),
		dumpParser: dumpParser,
	}
	return m
}

// NewPerCPUHashMap creates a new Map type of "per CPU hash" - object representing a BPF map
// The number of cpus is used to have the size representation of a value when
// a lookup is made on this map types.
func NewPerCPUHashMap(name string, mapKey MapKey, keySize int, mapValue MapValue, valueSize, cpus, maxEntries int, flags uint32, innerID uint32, dumpParser DumpParser) *Map {
	m := &Map{
		MapInfo: MapInfo{
			MapType:       BPF_MAP_TYPE_PERCPU_HASH,
			MapKey:        mapKey,
			KeySize:       uint32(keySize),
			MapValue:      mapValue,
			ReadValueSize: uint32(valueSize * cpus),
			ValueSize:     uint32(valueSize),
			MaxEntries:    uint32(maxEntries),
			Flags:         flags,
			InnerID:       innerID,
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

func (m *Map) commonName() string {
	if m.cachedCommonName != "" {
		return m.cachedCommonName
	}

	m.cachedCommonName = extractCommonName(m.name)
	return m.cachedCommonName
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

// Name returns the basename of this map.
func (m *Map) Name() string {
	return m.name
}

// Path returns the path to this map on the filesystem.
func (m *Map) Path() (string, error) {
	if err := m.setPathIfUnset(); err != nil {
		return "", err
	}

	return m.path, nil
}

// Unpin attempts to unpin (remove) the map from the filesystem.
func (m *Map) Unpin() error {
	path, err := m.Path()
	if err != nil {
		return err
	}

	return os.RemoveAll(path)
}

// UnpinIfExists tries to unpin (remove) the map only if it exists.
func (m *Map) UnpinIfExists() error {
	found, err := m.exist()
	if err != nil {
		return err
	}

	if !found {
		return nil
	}

	return m.Unpin()
}

// DeepEquals compares the current map against another map to see that the
// attributes of the two maps are the same.
func (m *Map) DeepEquals(other *Map) bool {
	return m.name == other.name &&
		m.path == other.path &&
		m.NonPersistent == other.NonPersistent &&
		reflect.DeepEqual(m.MapInfo, other.MapInfo)
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
			info.ReadValueSize = uint32(value)
		} else if n, err := fmt.Sscanf(line, "max_entries:\t%d", &value); n == 1 && err == nil {
			info.MaxEntries = uint32(value)
		} else if n, err := fmt.Sscanf(line, "map_flags:\t0x%x", &value); n == 1 && err == nil {
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

// OpenMap opens the given bpf map and generates the Map info based in the
// information stored in the bpf map.
// *Warning*: Calling this function requires the caller to properly setup
// the MapInfo.MapKey and MapInfo.MapValues fields as those structures are not
// stored in the bpf map.
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

// EndParallelMode ends the parallel mode of a map
func (m *Map) EndParallelMode() {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.inParallelMode {
		m.inParallelMode = false
		m.scopedLogger().Debug("End of parallel mode")
	}
}

// OpenParallel is similar to OpenOrCreate() but prepares the existing map to
// be faded out while a new map is taking over. This can be used if a map is
// shared between multiple consumers and the context of the shared map is
// changing. Any update to the shared map would impact all consumers and
// consumers can only be updated one by one. Parallel mode allows for consumers
// to continue using the old version of the map until the consumer is updated
// to use the new version.
func (m *Map) OpenParallel() (bool, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.fd != 0 {
		return false, fmt.Errorf("OpenParallel() called on already open map")
	}

	if err := m.setPathIfUnset(); err != nil {
		return false, err
	}

	if _, err := os.Stat(m.path); err == nil {
		err := os.Remove(m.path)
		if err != nil {
			log.WithError(err).Warning("Unable to remove BPF map for parallel operation")
			// Fall back to non-parallel mode
		} else {
			m.scopedLogger().Debug("Opening map in parallel mode")
			m.inParallelMode = true
		}
	}

	return m.openOrCreate(true)
}

// OpenOrCreate attempts to open the Map, or if it does not yet exist, create
// the Map. If the existing map's attributes such as map type, key/value size,
// capacity, etc. do not match the Map's attributes, then the map will be
// deleted and reopened without any attempt to retain its previous contents.
// If the map is marked as non-persistent, it will always be recreated.
//
// If the map type is MapTypeLRUHash or MapTypeLPMTrie and the kernel lacks
// support for this map type, then the map will be opened as MapTypeHash
// instead. Note that the BPF code that interacts with this map *MUST* be
// structured in such a way that the map is declared as the same type based on
// the same probe logic (eg HAVE_LRU_MAP_TYPE, HAVE_LPM_MAP_TYPE).
//
// For code that uses an LPMTrie, the BPF code must also use macros to retain
// the "longest prefix match" behaviour on top of the hash maps, for example
// via LPM_LOOKUP_FN() (see bpf/lib/maps.h).
//
// Returns whether the map was deleted and recreated, or an optional error.
func (m *Map) OpenOrCreate() (bool, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.openOrCreate(true)
}

// OpenOrCreateUnpinned is similar to OpenOrCreate (see above) but without
// pinning the map to the file system if it had to be created.
func (m *Map) OpenOrCreateUnpinned() (bool, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.openOrCreate(false)
}

// Create is similar to OpenOrCreate, but closes the map after creating or
// opening it.
func (m *Map) Create() (bool, error) {
	isNew, err := m.OpenOrCreate()
	if err != nil {
		return isNew, err
	}
	return isNew, m.Close()
}

func (m *Map) openOrCreate(pin bool) (bool, error) {
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

	mapType := GetMapType(m.MapType)
	flags := m.Flags | GetPreAllocateMapFlags(mapType)
	fd, isNew, err := OpenOrCreateMap(m.path, int(mapType), m.KeySize, m.ValueSize, m.MaxEntries, flags, m.InnerID, pin)
	if err != nil {
		return false, err
	}

	registerMap(m.path, m)

	m.fd = fd
	m.MapType = mapType
	m.Flags = flags
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
	m.MapType = GetMapType(m.MapType)
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

// Reopen attempts to close and re-open the received map.
func (m *Map) Reopen() error {
	m.Close()
	return m.Open()
}

type DumpParser func(key []byte, value []byte, mapKey MapKey, mapValue MapValue) (MapKey, MapValue, error)
type DumpCallback func(key MapKey, value MapValue)
type MapValidator func(path string) (bool, error)

// DumpWithCallback iterates over the Map and calls the given callback
// function on each iteration. That callback function is receiving the
// actual key and value. The callback function should consider creating a
// deepcopy of the key and value on between each iterations to avoid memory
// corruption.
func (m *Map) DumpWithCallback(cb DumpCallback) error {
	m.lock.RLock()
	defer m.lock.RUnlock()

	key := make([]byte, m.KeySize)
	nextKey := make([]byte, m.KeySize)
	value := make([]byte, m.ReadValueSize)

	if err := m.Open(); err != nil {
		return err
	}

	if err := GetFirstKey(m.fd, unsafe.Pointer(&nextKey[0])); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}

	mk := m.MapKey.DeepCopyMapKey()
	mv := m.MapValue.DeepCopyMapValue()

	bpfCurrentKey := bpfAttrMapOpElem{
		mapFd: uint32(m.fd),
		key:   uint64(uintptr(unsafe.Pointer(&key[0]))),
		value: uint64(uintptr(unsafe.Pointer(&nextKey[0]))),
	}
	bpfCurrentKeyPtr := unsafe.Pointer(&bpfCurrentKey)
	bpfCurrentKeySize := unsafe.Sizeof(bpfCurrentKey)

	bpfNextKey := bpfAttrMapOpElem{
		mapFd: uint32(m.fd),
		key:   uint64(uintptr(unsafe.Pointer(&nextKey[0]))),
		value: uint64(uintptr(unsafe.Pointer(&value[0]))),
	}

	bpfNextKeyPtr := unsafe.Pointer(&bpfNextKey)
	bpfNextKeySize := unsafe.Sizeof(bpfNextKey)

	for {
		err := LookupElementFromPointers(m.fd, bpfNextKeyPtr, bpfNextKeySize)
		if err != nil {
			return err
		}

		mk, mv, err = m.dumpParser(nextKey, value, mk, mv)
		if err != nil {
			return err
		}

		if cb != nil {
			cb(mk, mv)
		}

		copy(key, nextKey)

		if err := GetNextKeyFromPointers(m.fd, bpfCurrentKeyPtr, bpfCurrentKeySize); err != nil {
			if err == io.EOF { // end of map, we're done iterating
				return nil
			}
			return err
		}
	}
}

// DumpWithCallbackIfExists is similar to DumpWithCallback, but returns earlier
// if the given map does not exist.
func (m *Map) DumpWithCallbackIfExists(cb DumpCallback) error {
	found, err := m.exist()
	if err != nil {
		return err
	}

	if found {
		return m.DumpWithCallback(cb)
	}

	return nil
}

// DumpReliablyWithCallback is similar to DumpWithCallback, but performs
// additional tracking of the current and recently seen keys, so that if an
// element is removed from the underlying kernel map during the dump, the dump
// can continue from a recently seen key rather than restarting from scratch.
// In addition, it caps the maximum number of map entry iterations at 4 times
// the maximum map size. If this limit is reached, ErrMaxLookup is returned.
//
// The caller must provide a callback for handling each entry, and a stats
// object initialized via a call to NewDumpStats().
func (m *Map) DumpReliablyWithCallback(cb DumpCallback, stats *DumpStats) error {
	var (
		prevKey    = make([]byte, m.KeySize)
		currentKey = make([]byte, m.KeySize)
		nextKey    = make([]byte, m.KeySize)
		value      = make([]byte, m.ReadValueSize)

		prevKeyValid = false
	)
	stats.start()
	defer stats.finish()

	if err := m.Open(); err != nil {
		return err
	}

	if err := GetFirstKey(m.fd, unsafe.Pointer(&currentKey[0])); err != nil {
		stats.Lookup = 1
		if err == io.EOF {
			// map is empty, nothing to clean up.
			stats.Completed = true
			return nil
		}
		return err
	}

	mk := m.MapKey.DeepCopyMapKey()
	mv := m.MapValue.DeepCopyMapValue()

	bpfCurrentKey := bpfAttrMapOpElem{
		mapFd: uint32(m.fd),
		key:   uint64(uintptr(unsafe.Pointer(&currentKey[0]))),
		value: uint64(uintptr(unsafe.Pointer(&value[0]))),
	}
	bpfCurrentKeyPtr := unsafe.Pointer(&bpfCurrentKey)
	bpfCurrentKeySize := unsafe.Sizeof(bpfCurrentKey)

	bpfNextKey := bpfAttrMapOpElem{
		mapFd: uint32(m.fd),
		key:   uint64(uintptr(unsafe.Pointer(&currentKey[0]))),
		value: uint64(uintptr(unsafe.Pointer(&nextKey[0]))),
	}

	bpfNextKeyPtr := unsafe.Pointer(&bpfNextKey)
	bpfNextKeySize := unsafe.Sizeof(bpfNextKey)

	// maxLookup is an upper bound limit to prevent backtracking forever
	// when iterating over the map's elements (the map might be concurrently
	// updated while being iterated)
	maxLookup := stats.MaxEntries * 4

	// this loop stops when all elements have been iterated
	// (GetNextKeyFromPointers returns io.EOF) OR, in order to avoid hanging if
	// the map is continuously updated, when maxLookup has been reached
	for stats.Lookup = 1; stats.Lookup <= maxLookup; stats.Lookup++ {
		// currentKey was returned by GetFirstKey()/GetNextKeyFromPointers()
		// so we know it existed in the map, but it may have been deleted by a
		// concurrent map operation. If currentKey is no longer in the map,
		// nextKey will be the first key in the map again. Use the nextKey only
		// if we still find currentKey in the Lookup() after the
		// GetNextKeyFromPointers() call, this way we know nextKey is NOT the
		// first key in the map.
		nextKeyErr := GetNextKeyFromPointers(m.fd, bpfNextKeyPtr, bpfNextKeySize)
		err := LookupElementFromPointers(m.fd, bpfCurrentKeyPtr, bpfCurrentKeySize)
		if err != nil {
			stats.LookupFailed++
			// Restarting from a invalid key starts the iteration again from the beginning.
			// If we have a previously found key, try to restart from there instead
			if prevKeyValid {
				copy(currentKey, prevKey)
				// Restart from a given previous key only once, otherwise if the prevKey is
				// concurrently deleted we might loop forever trying to look it up.
				prevKeyValid = false
				stats.KeyFallback++
			} else {
				// Depending on exactly when currentKey was deleted from the
				// map, nextKey may be the actual key element after the deleted
				// one, or the first element in the map.
				copy(currentKey, nextKey)
				stats.Interrupted++
			}
			continue
		}

		mk, mv, err = m.dumpParser(currentKey, value, mk, mv)
		if err != nil {
			stats.Interrupted++
			return err
		}

		if cb != nil {
			cb(mk, mv)
		}

		if nextKeyErr != nil {
			if nextKeyErr == io.EOF {
				stats.Completed = true
				return nil // end of map, we're done iterating
			}
			return nextKeyErr
		}

		// remember the last found key
		copy(prevKey, currentKey)
		prevKeyValid = true
		// continue from the next key
		copy(currentKey, nextKey)
	}

	return ErrMaxLookup
}

// Dump returns the map (type map[string][]string) which contains all
// data stored in BPF map.
func (m *Map) Dump(hash map[string][]string) error {
	callback := func(key MapKey, value MapValue) {
		// No need to deep copy since we are creating strings.
		hash[key.String()] = append(hash[key.String()], value.String())
	}

	if err := m.DumpWithCallback(callback); err != nil {
		return err
	}

	return nil
}

// DumpIfExists dumps the contents of the map into hash via Dump() if the map
// file exists
func (m *Map) DumpIfExists(hash map[string][]string) error {
	found, err := m.exist()
	if err != nil {
		return err
	}

	if found {
		return m.Dump(hash)
	}

	return nil
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
	if option.Config.MetricsConfig.BPFMapOps {
		metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpUpdate, metrics.Error2Outcome(err)).Inc()
	}
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

// Delete deletes the map entry corresponding to the given key.
func (m *Map) Delete(key MapKey) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	var err error
	defer m.deleteCacheEntry(key, err)

	if err = m.Open(); err != nil {
		return err
	}

	_, errno := deleteElement(m.fd, key.GetKeyPtr())
	if option.Config.MetricsConfig.BPFMapOps {
		metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpDelete, metrics.Errno2Outcome(errno)).Inc()
	}
	if errno != 0 {
		err = fmt.Errorf("unable to delete element %s from map %s: %w", key, m.name, errno)
	}
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

	mk := m.MapKey.DeepCopyMapKey()
	mv := m.MapValue.DeepCopyMapValue()

	for {
		if err := GetFirstKey(m.fd, unsafe.Pointer(&nextKey[0])); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		err := DeleteElement(m.fd, unsafe.Pointer(&nextKey[0]))

		mk, _, err2 := m.dumpParser(nextKey, []byte{}, mk, mv)
		if err2 == nil {
			m.deleteCacheEntry(mk, err)
		} else {
			log.WithError(err2).Warningf("Unable to correlate iteration key %v with cache entry. Inconsistent cache.", nextKey)
		}

		if err != nil {
			return err
		}
	}
}

// GetNextKey returns the next key in the Map after key.
func (m *Map) GetNextKey(key MapKey, nextKey MapKey) error {
	if err := m.Open(); err != nil {
		return err
	}

	err := GetNextKey(m.fd, key.GetKeyPtr(), nextKey.GetKeyPtr())
	if option.Config.MetricsConfig.BPFMapOps {
		metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpGetNextKey, metrics.Error2Outcome(err)).Inc()
	}
	return err
}

// ConvertKeyValue converts key and value from bytes to given Golang struct pointers.
func ConvertKeyValue(bKey []byte, bValue []byte, key MapKey, value MapValue) (MapKey, MapValue, error) {

	if len(bKey) > 0 {
		if err := binary.Read(bKey, byteorder.Native, key); err != nil {
			return nil, nil, fmt.Errorf("Unable to convert key: %s", err)
		}
	}

	if len(bValue) > 0 {
		if err := binary.Read(bValue, byteorder.Native, value); err != nil {
			return nil, nil, fmt.Errorf("Unable to convert value: %s", err)
		}
	}

	return key, value, nil
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
func (m *Map) resolveErrors(ctx context.Context) error {
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
			if option.Config.MetricsConfig.BPFMapOps {
				metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpUpdate, metrics.Error2Outcome(err)).Inc()
			}
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
			if option.Config.MetricsConfig.BPFMapOps {
				metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpDelete, metrics.Error2Outcome(err)).Inc()
			}
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

// CheckAndUpgrade checks the received map's properties (for the map currently
// loaded into the kernel) against the desired properties, and if they do not
// match, deletes the map.
//
// Returns true if the map was upgraded.
func (m *Map) CheckAndUpgrade(desired *MapInfo) bool {
	desiredMapType := GetMapType(desired.MapType)
	desired.Flags |= GetPreAllocateMapFlags(desired.MapType)

	return objCheck(
		m.fd,
		m.path,
		int(desiredMapType),
		desired.KeySize,
		desired.ValueSize,
		desired.MaxEntries,
		desired.Flags,
	)
}

func (m *Map) exist() (bool, error) {
	path, err := m.Path()
	if err != nil {
		return false, err
	}

	if _, err := os.Stat(path); err == nil {
		return true, nil
	}

	return false, nil
}

// UnpinMapIfExists unpins the given map identified by name.
// If the map doesn't exist, returns success.
func UnpinMapIfExists(name string) error {
	path := MapPath(name)

	if _, err := os.Stat(path); err != nil {
		// Map doesn't exist
		return nil
	}

	return os.RemoveAll(path)
}
