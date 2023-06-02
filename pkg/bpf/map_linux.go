// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf/binary"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/spanstat"
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
	// this value and the ValueSize values can be different for MapTypePerCPUHash.
	ReadValueSize uint32
	ValueSize     uint32
	MaxEntries    uint32
	Flags         uint32
	InnerSpec     *ebpf.MapSpec
}

type cacheEntry struct {
	Key   MapKey
	Value MapValue

	DesiredAction DesiredAction
	LastError     error
}

type Map struct {
	MapInfo
	m         *ebpf.Map
	innerSpec *ebpf.MapSpec

	name string
	path string
	lock lock.RWMutex

	// cachedCommonName is the common portion of the name excluding any
	// endpoint ID
	cachedCommonName string

	// enableSync is true when synchronization retries have been enabled.
	enableSync bool

	// DumpParser is a function for parsing keys and values from BPF maps
	DumpParser DumpParser

	// withValueCache is true when map cache has been enabled
	withValueCache bool

	// cache as key/value entries when map cache is enabled or as key-only when
	// pressure metric is enabled
	cache map[string]*cacheEntry

	// errorResolverLastScheduled is the timestamp when the error resolver
	// was last scheduled
	errorResolverLastScheduled time.Time

	// outstandingErrors is the number of outsanding errors syncing with
	// the kernel
	outstandingErrors int

	// pressureGauge is a metric that tracks the pressure on this map
	pressureGauge *metrics.GaugeWithThreshold

	// is true when events buffer is enabled.
	eventsBufferEnabled bool

	// contains optional event buffer which stores last n bpf map events.
	events *eventsBuffer
}

// NewMap creates a new Map instance - object representing a BPF map
func NewMap(name string, mapType MapType, mapKey MapKey, keySize int,
	mapValue MapValue, valueSize, maxEntries int, flags uint32, dumpParser DumpParser) *Map {

	if size := reflect.TypeOf(mapKey).Elem().Size(); size != uintptr(keySize) {
		panic(fmt.Sprintf("Invalid %s map key size (%d != %d)", name, size, keySize))
	}

	if size := reflect.TypeOf(mapValue).Elem().Size(); size != uintptr(valueSize) {
		panic(fmt.Sprintf("Invalid %s map value size (%d != %d)", name, size, valueSize))
	}

	return &Map{
		MapInfo: MapInfo{
			MapType:       mapType,
			MapKey:        mapKey,
			KeySize:       uint32(keySize),
			MapValue:      mapValue,
			ReadValueSize: uint32(valueSize),
			ValueSize:     uint32(valueSize),
			MaxEntries:    uint32(maxEntries),
			Flags:         flags,
		},
		name:       path.Base(name),
		DumpParser: dumpParser,
	}
}

// NewMap creates a new Map instance - object representing a BPF map
func NewMapWithInnerSpec(name string, mapType MapType, mapKey MapKey, mapValue MapValue, maxEntries int, flags uint32,
	innerSpec *ebpf.MapSpec, dumpParser DumpParser) *Map {

	keySize := reflect.TypeOf(mapKey).Elem().Size()
	valueSize := reflect.TypeOf(mapValue).Elem().Size()

	return &Map{
		MapInfo: MapInfo{
			MapType:       mapType,
			MapKey:        mapKey,
			KeySize:       uint32(keySize),
			MapValue:      mapValue,
			ReadValueSize: uint32(valueSize),
			ValueSize:     uint32(valueSize),
			MaxEntries:    uint32(maxEntries),
			Flags:         flags,
		},
		name:       path.Base(name),
		innerSpec:  innerSpec,
		DumpParser: dumpParser,
	}
}

func (m *Map) commonName() string {
	if m.cachedCommonName != "" {
		return m.cachedCommonName
	}

	m.cachedCommonName = extractCommonName(m.name)
	return m.cachedCommonName
}

func (m *Map) NonPrefixedName() string {
	return strings.TrimPrefix(m.name, metrics.Namespace+"_")
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
	if m.cache == nil {
		m.cache = map[string]*cacheEntry{}
	}
	m.withValueCache = true
	m.enableSync = true
	return m
}

// WithEvents enables use of the event buffer, if the buffer is enabled.
// This stores all map events (i.e. add/update/delete) in a bounded event buffer.
// If eventTTL is not zero, than events that are older than the TTL
// will periodically be removed from the buffer.
// Enabling events will use aprox proportional to 100MB for every million capacity
// in maxSize.
//
// TODO: The IPCache map have many periodic update events added by a controller for entries such as the 0.0.0.0/0 range.
// These fill the event buffer with possibly unnecessary events.
// We should either provide an option to aggregate these events, ignore hem from the ipcache event buffer or store them in a separate buffer.
func (m *Map) WithEvents(c option.BPFEventBufferConfig) *Map {
	if !c.Enabled {
		return m
	}
	m.scopedLogger().WithFields(logrus.Fields{
		"size": c.MaxSize,
		"ttl":  c.TTL,
	}).Debug("enabling events buffer")
	m.eventsBufferEnabled = true
	m.initEventsBuffer(c.MaxSize, c.TTL)
	return m
}

// WithPressureMetricThreshold enables the tracking of a metric that measures
// the pressure of this map. This metric is only reported if over the
// threshold.
func (m *Map) WithPressureMetricThreshold(threshold float64) *Map {
	// When pressure metric is enabled, we keep track of map keys in cache
	if m.cache == nil {
		m.cache = map[string]*cacheEntry{}
	}

	m.pressureGauge = metrics.NewBPFMapPressureGauge(m.NonPrefixedName(), threshold)

	return m
}

// WithPressureMetric enables tracking and reporting of this map pressure with
// threshold 0.
func (m *Map) WithPressureMetric() *Map {
	return m.WithPressureMetricThreshold(0.0)
}

func (m *Map) updatePressureMetric() {
	if m.pressureGauge == nil {
		return
	}

	// Do a lazy check of MetricsConfig as it is not available at map static
	// initialization.
	if !option.Config.MetricsConfig.BPFMapPressure {
		if !m.withValueCache {
			m.cache = nil
		}
		m.pressureGauge = nil
		return
	}

	pvalue := float64(len(m.cache)) / float64(m.MaxEntries)
	m.pressureGauge.Set(pvalue)
}

func (m *Map) FD() int {
	return m.m.FD()
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
func OpenMap(pinPath string) (*Map, error) {
	if !path.IsAbs(pinPath) {
		return nil, fmt.Errorf("pinPath must be absolute: %s", pinPath)
	}

	em, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return nil, err
	}

	m := &Map{
		MapInfo: MapInfo{
			MapType:       MapType(em.Type()),
			KeySize:       em.KeySize(),
			ValueSize:     em.ValueSize(),
			ReadValueSize: em.ValueSize(),
			MaxEntries:    em.MaxEntries(),
			Flags:         em.Flags(),
		},
		m:    em,
		name: path.Base(pinPath),
		path: pinPath,
	}

	registerMap(pinPath, m)

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

// Recreate removes any pin at the Map's pin path, recreates and re-pins it.
func (m *Map) Recreate() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.m != nil {
		return fmt.Errorf("map already open: %s", m.name)
	}

	if err := m.setPathIfUnset(); err != nil {
		return err
	}

	if err := os.Remove(m.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing pinned map %s: %w", m.name, err)
	}

	m.scopedLogger().Infof("Removed map pin at %s, recreating and re-pinning map %s", m.path, m.name)

	return m.openOrCreate(true)
}

// OpenOrCreate attempts to open the Map, or if it does not yet exist, create
// the Map. If the existing map's attributes such as map type, key/value size,
// capacity, etc. do not match the Map's attributes, then the map will be
// deleted and reopened without any attempt to retain its previous contents.
// If the map is marked as non-persistent, it will always be recreated.
//
// Returns whether the map was deleted and recreated, or an optional error.
func (m *Map) OpenOrCreate() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.openOrCreate(true)
}

// CreateUnpinned creates the map without pinning it to the file system.
//
// TODO(tb): Remove this when all map creation takes MapSpec.
func (m *Map) CreateUnpinned() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.openOrCreate(false)
}

// Create is similar to OpenOrCreate, but closes the map after creating or
// opening it.
func (m *Map) Create() error {
	if err := m.OpenOrCreate(); err != nil {
		return err
	}
	return m.Close()
}

func (m *Map) openOrCreate(pin bool) error {
	if m.m != nil {
		return nil
	}

	if err := m.setPathIfUnset(); err != nil {
		return err
	}

	m.Flags |= GetPreAllocateMapFlags(m.MapType)

	spec := &ebpf.MapSpec{
		Name:       m.name,
		Type:       ebpf.MapType(m.MapType),
		KeySize:    m.KeySize,
		ValueSize:  m.ValueSize,
		MaxEntries: m.MaxEntries,
		Flags:      m.Flags,
		InnerMap:   m.innerSpec,
	}
	if pin {
		spec.Pinning = ebpf.PinByName
	}

	em, err := OpenOrCreateMap(spec, path.Dir(m.path))
	if err != nil {
		return err
	}

	registerMap(m.path, m)

	m.m = em

	return nil
}

// Open opens the BPF map. All calls to Open() are serialized due to acquiring
// m.lock
func (m *Map) Open() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.open()
}

// open opens the BPF map. It is identical to Open() but should be used when
// m.lock is already held. open() may only be used if m.lock is held for
// writing.
func (m *Map) open() error {
	if m.m != nil {
		return nil
	}

	if err := m.setPathIfUnset(); err != nil {
		return err
	}

	em, err := ebpf.LoadPinnedMap(m.path, nil)
	if err != nil {
		return fmt.Errorf("loading pinned map %s: %w", m.path, err)
	}

	registerMap(m.path, m)

	m.m = em

	return nil
}

func (m *Map) Close() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.enableSync {
		mapControllers.RemoveController(m.controllerName())
	}

	if m.m != nil {
		m.m.Close()
		m.m = nil
	}

	unregisterMap(m.path, m)

	return nil
}

func (m *Map) NextKey(key, nextKeyOut interface{}) error {
	var duration *spanstat.SpanStat
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		duration = spanstat.Start()
	}

	err := m.m.NextKey(key, nextKeyOut)

	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpGetNextKey, metrics.Error2Outcome(err)).Observe(duration.End(err == nil).Total().Seconds())
	}

	return err
}

type DumpParser func(key []byte, value []byte, mapKey MapKey, mapValue MapValue) (MapKey, MapValue, error)
type DumpCallback func(key MapKey, value MapValue)
type MapValidator func(path string) (bool, error)

// DumpWithCallback iterates over the Map and calls the given callback
// function on each iteration. That callback function is receiving the
// actual key and value. The callback function should consider creating a
// deepcopy of the key and value on between each iterations to avoid memory
// corruption.
//
// TODO(tb): This package currently doesn't support dumping per-cpu maps, as
// ReadValueSize is always set to the size of a single value.
func (m *Map) DumpWithCallback(cb DumpCallback) error {
	if err := m.Open(); err != nil {
		return err
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	key := make([]byte, m.KeySize)
	value := make([]byte, m.ReadValueSize)

	mk := m.MapKey.DeepCopyMapKey()
	mv := m.MapValue.DeepCopyMapValue()

	i := m.m.Iterate()
	for i.Next(&key, &value) {
		// TODO(tb): Remove DumpParser altogether if it's only ever used with
		// bpf.ConvertKeyValue. It does binary.Read and Iterate().Next() already
		// does that ootb.
		var err error
		mk, mv, err = m.DumpParser(key, value, mk, mv)
		if err != nil {
			return err
		}

		if cb != nil {
			cb(mk, mv)
		}
	}

	return i.Err()
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

	// Get the first map key.
	if err := m.NextKey(nil, unsafe.Pointer(&currentKey[0])); err != nil {
		stats.Lookup = 1
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			// Empty map, nothing to iterate.
			stats.Completed = true
			return nil
		}
	}

	mk := m.MapKey.DeepCopyMapKey()
	mv := m.MapValue.DeepCopyMapValue()

	// maxLookup is an upper bound limit to prevent backtracking forever
	// when iterating over the map's elements (the map might be concurrently
	// updated while being iterated)
	maxLookup := stats.MaxEntries * 4

	// This loop stops when all elements have been iterated (Map.NextKey() returns
	// ErrKeyNotExist) OR, in order to avoid hanging if
	// the map is continuously updated, when maxLookup has been reached
	for stats.Lookup = 1; stats.Lookup <= maxLookup; stats.Lookup++ {
		// currentKey was set by the first m.NextKey() above. We know it existed in
		// the map, but it may have been deleted by a concurrent map operation.
		//
		// If currentKey is no longer in the map, nextKey may be the first key in
		// the map again. Continue with nextKey only if we still find currentKey in
		// the Lookup() after the call to m.NextKey(), this way we know nextKey is
		// NOT the first key in the map and iteration hasn't reset.
		nextKeyErr := m.NextKey(unsafe.Pointer(&currentKey[0]), unsafe.Pointer(&nextKey[0]))

		if err := m.m.Lookup(unsafe.Pointer(&currentKey[0]), unsafe.Pointer(&value[0])); err != nil {
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

		var err error
		mk, mv, err = m.DumpParser(currentKey, value, mk, mv)
		if err != nil {
			stats.Interrupted++
			return err
		}

		if cb != nil {
			cb(mk, mv)
		}

		if nextKeyErr != nil {
			if errors.Is(nextKeyErr, ebpf.ErrKeyNotExist) {
				stats.Completed = true
				return nil // end of map, we're done iterating
			}
			return nextKeyErr
		}

		// Prepare keys to move to the next iteration.
		copy(prevKey, currentKey)
		copy(currentKey, nextKey)
		prevKeyValid = true
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
	if err := m.Open(); err != nil {
		return nil, err
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	var duration *spanstat.SpanStat
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		duration = spanstat.Start()
	}

	value := key.NewValue()
	err := m.m.Lookup(key.GetKeyPtr(), value.GetValuePtr())

	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpLookup, metrics.Error2Outcome(err)).Observe(duration.End(err == nil).Total().Seconds())
	}

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
		desiredAction := OK
		if err != nil {
			desiredAction = Insert
		}
		entry := &cacheEntry{
			Key:           key,
			Value:         value,
			DesiredAction: desiredAction,
			LastError:     err,
		}
		m.addToEventsLocked(MapUpdate, *entry)

		if m.cache == nil {
			return
		}

		if m.withValueCache {
			if err != nil {
				m.scheduleErrorResolver()
			}
			m.cache[key.String()] = &cacheEntry{
				Key:           key,
				Value:         value,
				DesiredAction: desiredAction,
				LastError:     err,
			}
			m.updatePressureMetric()
		} else if err == nil {
			m.cache[key.String()] = nil
			m.updatePressureMetric()
		}
	}()

	if err = m.open(); err != nil {
		return err
	}

	err = m.m.Update(key.GetKeyPtr(), value.GetValuePtr(), ebpf.UpdateAny)

	if option.Config.MetricsConfig.BPFMapOps {
		metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpUpdate, metrics.Error2Outcome(err)).Inc()
	}

	if err != nil {
		return fmt.Errorf("update map %s: %w", m.Name(), err)
	}

	return nil
}

// deleteMapEvent is run at every delete map event.
// If cache is enabled, it will update the cache to reflect the delete.
// As well, if event buffer is enabled, it adds a new event to the buffer.
func (m *Map) deleteMapEvent(key MapKey, err error) {
	m.addToEventsLocked(MapDelete, cacheEntry{
		Key:           key,
		DesiredAction: Delete,
		LastError:     err,
	})
	m.deleteCacheEntry(key, err)
}

func (m *Map) deleteAllMapEvent() {
	m.addToEventsLocked(MapDeleteAll, cacheEntry{})
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
	} else if !m.withValueCache {
		return
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

// delete deletes the map entry corresponding to the given key. If ignoreMissing
// is set to true and the entry was not found, the error metric is not
// incremented for missing entries and nil error is returned.
func (m *Map) delete(key MapKey, ignoreMissing bool) (_ bool, err error) {
	defer func() {
		m.deleteMapEvent(key, err)
		if err != nil {
			m.updatePressureMetric()
		}
	}()

	if err = m.open(); err != nil {
		return false, err
	}

	var duration *spanstat.SpanStat
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		duration = spanstat.Start()
	}

	err = m.m.Delete(key.GetKeyPtr())

	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpDelete, metrics.Error2Outcome(err)).Observe(duration.End(err == nil).Total().Seconds())
	}

	if errors.Is(err, ebpf.ErrKeyNotExist) && ignoreMissing {
		// Error and metrics handling is skipped in case ignoreMissing is set and
		// the map key did not exist. This removes false positives in the delete
		// metrics and skips the deferred cleanup of nonexistent entries. This
		// situation occurs at least in the context of cleanup of NAT mappings from
		// CT GC.
		return false, nil
	}

	if option.Config.MetricsConfig.BPFMapOps {
		// err can be nil or any error other than ebpf.ErrKeyNotExist.
		metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpDelete, metrics.Error2Outcome(err)).Inc()
	}

	if err != nil {
		return false, fmt.Errorf("unable to delete element %s from map %s: %w", key, m.name, err)
	}

	return true, nil
}

// SilentDelete deletes the map entry corresponding to the given key.
// If a map entry is not found this returns (false, nil).
func (m *Map) SilentDelete(key MapKey) (deleted bool, err error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.delete(key, true)
}

// Delete deletes the map entry corresponding to the given key.
func (m *Map) Delete(key MapKey) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	_, err := m.delete(key, false)
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
	defer m.updatePressureMetric()
	scopedLog := m.scopedLogger()
	scopedLog.Debug("deleting all entries in map")

	if m.withValueCache {
		// Mark all entries for deletion, upon successful deletion,
		// entries will be removed or the LastError will be updated
		for _, entry := range m.cache {
			entry.DesiredAction = Delete
			entry.LastError = fmt.Errorf("deletion pending")
		}
	}

	if err := m.open(); err != nil {
		return err
	}

	mk := m.MapKey.DeepCopyMapKey()
	mv := m.MapValue.DeepCopyMapValue()

	defer m.deleteAllMapEvent()

	key := make([]byte, m.KeySize)
	value := make([]byte, m.ReadValueSize)

	i := m.m.Iterate()
	for i.Next(&key, &value) {
		err := m.m.Delete(key)

		mk, _, err2 := m.DumpParser(key, []byte{}, mk, mv)
		if err2 == nil {
			m.deleteCacheEntry(mk, err)
		} else {
			log.WithError(err2).Warningf("Unable to correlate iteration key %v with cache entry. Inconsistent cache.", key)
		}

		if err != nil {
			return err
		}
	}

	return i.Err()
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

	if m.withValueCache {
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

func (m *Map) addToEventsLocked(action Action, entry cacheEntry) {
	if !m.eventsBufferEnabled {
		return
	}
	m.events.add(&Event{
		action:     action,
		Timestamp:  time.Now(),
		cacheEntry: entry,
	})
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

	if err := m.open(); err != nil {
		return err
	}

	scopedLogger := m.scopedLogger()
	scopedLogger.WithField("remaining", m.outstandingErrors).
		Debug("Starting periodic BPF map error resolver")

	resolved := 0
	scanned := 0
	nerr := 0
	for k, e := range m.cache {
		scanned++

		switch e.DesiredAction {
		case OK:
		case Insert:
			// Call into ebpf-go's Map.Update() directly, don't go through the cache.
			err := m.m.Update(e.Key.GetKeyPtr(), e.Value.GetValuePtr(), ebpf.UpdateAny)
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
				nerr++
			}
			m.cache[k] = e
			m.addToEventsLocked(MapUpdate, *e)
		case Delete:
			// Holding lock, issue direct delete on map.
			err := m.m.Delete(e.Key.GetKeyPtr())
			if option.Config.MetricsConfig.BPFMapOps {
				metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpDelete, metrics.Error2Outcome(err)).Inc()
			}
			if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
				delete(m.cache, k)
				resolved++
				m.outstandingErrors--
			} else {
				e.LastError = err
				nerr++
				m.cache[k] = e
			}

			m.addToEventsLocked(MapDelete, *e)
		}

		// bail out if maximum errors are reached to relax the map lock
		if nerr > maxSyncErrors {
			break
		}
	}

	m.updatePressureMetric()

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
	desired.Flags |= GetPreAllocateMapFlags(desired.MapType)

	return objCheck(
		m.FD(),
		m.path,
		desired.MapType,
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
