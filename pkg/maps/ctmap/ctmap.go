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

package ctmap

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-ct")

	// labelIPv6CTDumpInterrupts marks the count for conntrack dump resets (IPv6).
	labelIPv6CTDumpInterrupts = map[string]string{
		metrics.LabelDatapathArea:   "conntrack",
		metrics.LabelDatapathName:   "dump_interrupts",
		metrics.LabelDatapathFamily: "ipv6",
	}
	// labelIPv4CTDumpInterrupts marks the count for conntrack dump resets (IPv4).
	labelIPv4CTDumpInterrupts = map[string]string{
		metrics.LabelDatapathArea:   "conntrack",
		metrics.LabelDatapathName:   "dump_interrupts",
		metrics.LabelDatapathFamily: "ipv4",
	}

	mapInfo map[MapType]mapAttributes
	once    sync.Once
)

const (
	// mapCount counts the maximum number of CT maps that one endpoint may
	// access at once.
	mapCount = 4

	// Map names for TCP CT tables are retained from Cilium 1.0 naming
	// scheme to minimize disruption of ongoing connections during upgrade.
	MapNamePrefix     = "cilium_ct"
	MapNameTCP6       = MapNamePrefix + "6_"
	MapNameTCP4       = MapNamePrefix + "4_"
	MapNameTCP6Global = MapNameTCP6 + "global"
	MapNameTCP4Global = MapNameTCP4 + "global"

	// Map names for "any" protocols indicate CT for non-TCP protocols.
	MapNameAny6       = MapNamePrefix + "_any6_"
	MapNameAny4       = MapNamePrefix + "_any4_"
	MapNameAny6Global = MapNameAny6 + "global"
	MapNameAny4Global = MapNameAny4 + "global"

	MapNumEntriesLocal = 64000

	TUPLE_F_OUT     = 0
	TUPLE_F_IN      = 1
	TUPLE_F_RELATED = 2
	TUPLE_F_SERVICE = 4

	// MaxTime specifies the last possible time for GCFilter.Time
	MaxTime = math.MaxUint32

	noAction = iota
	deleteEntry

	metricsAlive   = "alive"
	metricsDeleted = "deleted"
)

var globalDeleteLock [MapTypeMax]lock.Mutex

type NatMap interface {
	Open() error
	Close() error
	DeleteMapping(key tuple.TupleKey) error
}

type mapAttributes struct {
	mapKey     bpf.MapKey
	keySize    int
	mapValue   bpf.MapValue
	valueSize  int
	maxEntries int
	parser     bpf.DumpParser
	bpfDefine  string
	natMap     NatMap
}

func setupMapInfo(mapType MapType, define string, mapKey bpf.MapKey, keySize int, maxEntries int, nat NatMap) {
	mapInfo[mapType] = mapAttributes{
		bpfDefine: define,
		mapKey:    mapKey,
		keySize:   keySize,
		// the value type is CtEntry for all CT maps
		mapValue:   &CtEntry{},
		valueSize:  int(unsafe.Sizeof(CtEntry{})),
		maxEntries: maxEntries,
		parser:     bpf.ConvertKeyValue,
		natMap:     nat,
	}
}

// initMapInfo builds the information about different CT maps for the
// combination of L3/L4 protocols, using the specified limits on TCP vs non-TCP
// maps.
func initMapInfo(tcpMaxEntries, anyMaxEntries int, v4, v6, lru bool) {
	mapInfo = make(map[MapType]mapAttributes)

	global4Map, global6Map := nat.GlobalMaps(v4, v6, lru)

	// SNAT also only works if the CT map is global so all local maps will be nil
	natMaps := map[MapType]NatMap{
		MapTypeIPv4TCPLocal:  nil,
		MapTypeIPv6TCPLocal:  nil,
		MapTypeIPv4TCPGlobal: global4Map,
		MapTypeIPv6TCPGlobal: global6Map,
		MapTypeIPv4AnyLocal:  nil,
		MapTypeIPv6AnyLocal:  nil,
		MapTypeIPv4AnyGlobal: global4Map,
		MapTypeIPv6AnyGlobal: global6Map,
	}

	setupMapInfo(MapType(MapTypeIPv4TCPLocal), "CT_MAP_TCP4",
		&CtKey4{}, int(unsafe.Sizeof(CtKey4{})),
		MapNumEntriesLocal, natMaps[MapTypeIPv4TCPLocal])

	setupMapInfo(MapType(MapTypeIPv6TCPLocal), "CT_MAP_TCP6",
		&CtKey6{}, int(unsafe.Sizeof(CtKey6{})),
		MapNumEntriesLocal, natMaps[MapTypeIPv6TCPLocal])

	setupMapInfo(MapType(MapTypeIPv4TCPGlobal), "CT_MAP_TCP4",
		&CtKey4Global{}, int(unsafe.Sizeof(CtKey4Global{})),
		tcpMaxEntries, natMaps[MapTypeIPv4TCPGlobal])

	setupMapInfo(MapType(MapTypeIPv6TCPGlobal), "CT_MAP_TCP6",
		&CtKey6Global{}, int(unsafe.Sizeof(CtKey6Global{})),
		tcpMaxEntries, natMaps[MapTypeIPv6TCPGlobal])

	setupMapInfo(MapType(MapTypeIPv4AnyLocal), "CT_MAP_ANY4",
		&CtKey4{}, int(unsafe.Sizeof(CtKey4{})),
		MapNumEntriesLocal, natMaps[MapTypeIPv4AnyLocal])

	setupMapInfo(MapType(MapTypeIPv6AnyLocal), "CT_MAP_ANY6",
		&CtKey6{}, int(unsafe.Sizeof(CtKey6{})),
		MapNumEntriesLocal, natMaps[MapTypeIPv6AnyLocal])

	setupMapInfo(MapType(MapTypeIPv4AnyGlobal), "CT_MAP_ANY4",
		&CtKey4Global{}, int(unsafe.Sizeof(CtKey4Global{})),
		anyMaxEntries, natMaps[MapTypeIPv4AnyGlobal])

	setupMapInfo(MapType(MapTypeIPv6AnyGlobal), "CT_MAP_ANY6",
		&CtKey6Global{}, int(unsafe.Sizeof(CtKey6Global{})),
		anyMaxEntries, natMaps[MapTypeIPv6AnyGlobal])
}

func getMapInfo(lru bool) map[MapType]mapAttributes {
	once.Do(func() {
		initMapInfo(option.CTMapEntriesGlobalTCPDefault,
			option.CTMapEntriesGlobalAnyDefault, option.Config.EnableIPv4,
			option.Config.EnableIPv6, lru)
	})
	return mapInfo
}

// CtEndpoint represents an endpoint for the functions required to manage
// conntrack maps for the endpoint.
type CtEndpoint interface {
	GetID() uint64
}

// Map represents an instance of a BPF connection tracking map.
type Map struct {
	bpf.Map

	mapType MapType
	// define maps to the macro used in the datapath portion for the map
	// name, for example 'CT_MAP4'.
	define string
}

// GCFilter contains the necessary fields to filter the CT maps.
// Filtering by endpoint requires both EndpointID to be > 0 and
// EndpointIP to be not nil.
type GCFilter struct {
	// RemoveExpired enables removal of all entries that have expired
	RemoveExpired bool

	// Time is the reference timestamp to reomove expired entries. If
	// RemoveExpired is true and lifetime is lesser than Time, the entry is
	// removed
	Time uint32

	// ValidIPs is the list of valid IPs to scrub all entries for which the
	// source or destination IP is *not* matching one of the valid IPs.
	// The key is the IP in string form: net.IP.String()
	ValidIPs map[string]struct{}

	// MatchIPs is the list of IPs to remove from the conntrack table
	MatchIPs map[string]struct{}

	// EmitCTEntry is called, when non-nil, if filtering by ValidIPs and MatchIPs
	// passes. It has no impact on CT GC, but can be used to iterate over valid
	// CT entries.
	EmitCTEntryCB EmitCTEntryCBFunc
}

// EmitCTEntryCBFunc is the type used for the EmitCTEntryCB callback in GCFilter
type EmitCTEntryCBFunc func(srcIP, dstIP net.IP, srcPort, dstPort uint16, nextHdr, flags uint8, entry *CtEntry)

// ToString iterates through Map m and writes the values of the ct entries in m
// to a string.
func (m *Map) DumpEntries() (string, error) {
	var buffer bytes.Buffer

	cb := func(k bpf.MapKey, v bpf.MapValue) {
		// No need to deep copy as the values are used to create new strings
		key := k.(CtKey)
		if !key.ToHost().Dump(&buffer, true) {
			return
		}
		value := v.(*CtEntry)
		buffer.WriteString(value.String())
	}
	// DumpWithCallback() must be called before buffer.String().
	err := m.DumpWithCallback(cb)
	return buffer.String(), err
}

func newMap(mapName string, mapType MapType, lru bool) *Map {
	info := getMapInfo(lru)
	result := &Map{
		Map: *bpf.NewMap(mapName,
			bpf.MapTypeLRUHash,
			info[mapType].mapKey,
			info[mapType].keySize,
			info[mapType].mapValue,
			info[mapType].valueSize,
			info[mapType].maxEntries,
			0, 0,
			info[mapType].parser,
		),
		mapType: mapType,
		define:  info[mapType].bpfDefine,
	}
	return result
}

func purgeCtEntry6(m *Map, key CtKey, natMap NatMap) error {
	err := m.Delete(key)
	if err == nil && natMap != nil {
		natMap.DeleteMapping(key.GetTupleKey())
	}
	return err
}

// doGC6 iterates through a CTv6 map and drops entries based on the given
// filter.
func doGC6(m *Map, filter *GCFilter) gcStats {
	// We don't need to check for LRU hashmap support since we're not creating the map.
	info := getMapInfo(true)
	natMap := info[m.mapType].natMap
	stats := statStartGc(m)
	defer stats.finish()

	if natMap != nil {
		err := natMap.Open()
		if err == nil {
			defer natMap.Close()
		} else {
			natMap = nil
		}
	}

	filterCallback := func(key bpf.MapKey, value bpf.MapValue) {
		entry := value.(*CtEntry)

		switch obj := key.(type) {
		case *CtKey6Global:
			currentKey6Global := obj
			// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
			// the destination of the packet received, therefore it's the packet's
			// destination IP
			action := filter.doFiltering(currentKey6Global.DestAddr.IP(), currentKey6Global.SourceAddr.IP(),
				currentKey6Global.DestPort, currentKey6Global.SourcePort,
				uint8(currentKey6Global.NextHeader), currentKey6Global.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry6(m, currentKey6Global, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey6Global.String()).Error("Unable to delete CT entry")
				} else {
					stats.deleted++
				}
			default:
				stats.aliveEntries++
			}
		case *CtKey6:
			currentKey6 := obj
			// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
			// the destination of the packet received, therefore it's the packet's
			// destination IP
			action := filter.doFiltering(currentKey6.DestAddr.IP(), currentKey6.SourceAddr.IP(),
				currentKey6.DestPort, currentKey6.SourcePort,
				uint8(currentKey6.NextHeader), currentKey6.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry6(m, currentKey6, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey6.String()).Error("Unable to delete CT entry")
				} else {
					stats.deleted++
				}
			default:
				stats.aliveEntries++
			}
		default:
			log.Warningf("Encountered unknown type while scanning conntrack table: %v", reflect.TypeOf(key))
		}
	}

	// See doGC4() comment.
	globalDeleteLock[m.mapType].Lock()
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)
	globalDeleteLock[m.mapType].Unlock()
	return stats
}

func purgeCtEntry4(m *Map, key CtKey, natMap NatMap) error {
	err := m.Delete(key)
	if err == nil && natMap != nil {
		natMap.DeleteMapping(key.GetTupleKey())
	}
	return err
}

// doGC4 iterates through a CTv4 map and drops entries based on the given
// filter.
func doGC4(m *Map, filter *GCFilter) gcStats {
	// We don't need to check for LRU hashmap support since we're not creating the map.
	info := getMapInfo(true)
	natMap := info[m.mapType].natMap
	stats := statStartGc(m)
	defer stats.finish()

	if natMap != nil {
		if err := natMap.Open(); err == nil {
			defer natMap.Close()
		} else {
			natMap = nil
		}
	}

	filterCallback := func(key bpf.MapKey, value bpf.MapValue) {
		entry := value.(*CtEntry)

		switch obj := key.(type) {
		case *CtKey4Global:
			currentKey4Global := obj
			// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
			// the destination of the packet received, therefore it's the packet's
			// destination IP
			action := filter.doFiltering(currentKey4Global.DestAddr.IP(), currentKey4Global.SourceAddr.IP(),
				currentKey4Global.DestPort, currentKey4Global.SourcePort,
				uint8(currentKey4Global.NextHeader), currentKey4Global.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry4(m, currentKey4Global, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey4Global.String()).Error("Unable to delete CT entry")
				} else {
					stats.deleted++
				}
			default:
				stats.aliveEntries++
			}
		case *CtKey4:
			currentKey4 := obj
			// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
			// the destination of the packet received, therefore it's the packet's
			// destination IP
			action := filter.doFiltering(currentKey4.DestAddr.IP(), currentKey4.SourceAddr.IP(),
				currentKey4.DestPort, currentKey4.SourcePort,
				uint8(currentKey4.NextHeader), currentKey4.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry4(m, currentKey4, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey4.String()).Error("Unable to delete CT entry")
				} else {
					stats.deleted++
				}
			default:
				stats.aliveEntries++
			}
		default:
			log.Warningf("Encountered unknown type while scanning conntrack table: %v", reflect.TypeOf(key))
		}
	}

	// We serialize the deletions in order to avoid forced map walk restarts
	// when keys are being evicted underneath us from concurrent go routines.
	globalDeleteLock[m.mapType].Lock()
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)
	globalDeleteLock[m.mapType].Unlock()
	return stats
}

func (f *GCFilter) doFiltering(srcIP, dstIP net.IP, srcPort, dstPort uint16, nextHdr, flags uint8, entry *CtEntry) (action int) {
	if f.RemoveExpired && entry.Lifetime < f.Time {
		return deleteEntry
	}

	if f.ValidIPs != nil {
		_, srcIPExists := f.ValidIPs[srcIP.String()]
		_, dstIPExists := f.ValidIPs[dstIP.String()]
		if !srcIPExists && !dstIPExists {
			return deleteEntry
		}
	}

	if f.MatchIPs != nil {
		_, srcIPExists := f.MatchIPs[srcIP.String()]
		_, dstIPExists := f.MatchIPs[dstIP.String()]
		if srcIPExists || dstIPExists {
			return deleteEntry
		}
	}

	if f.EmitCTEntryCB != nil {
		f.EmitCTEntryCB(srcIP, dstIP, srcPort, dstPort, nextHdr, flags, entry)
	}

	return noAction
}

func doGC(m *Map, filter *GCFilter) int {
	if m.mapType.isIPv6() {
		return int(doGC6(m, filter).deleted)
	} else if m.mapType.isIPv4() {
		return int(doGC4(m, filter).deleted)
	}
	log.Fatalf("Unsupported ct map type: %s", m.mapType.String())
	return 0
}

// GC runs garbage collection for map m with name mapType with the given filter.
// It returns how many items were deleted from m.
func GC(m *Map, filter *GCFilter) int {
	if filter.RemoveExpired {
		t, _ := bpf.GetMtime()
		tsec := t / 1000000000
		filter.Time = uint32(tsec)
	}

	return doGC(m, filter)
}

// Flush runs garbage collection for map m with the name mapType, deleting all
// entries. The specified map must be already opened using bpf.OpenMap().
func (m *Map) Flush() int {
	return doGC(m, &GCFilter{
		RemoveExpired: true,
		Time:          MaxTime,
	})
}

// DeleteIfUpgradeNeeded attempts to open the conntrack maps associated with
// the specified endpoint, and delete the maps from the filesystem if any
// properties do not match the properties defined in this package.
//
// The typical trigger for this is when, for example, the CT entry size changes
// from one version of Cilium to the next. When Cilium restarts, it may opt
// to restore endpoints from the prior life. Existing endpoints that use the
// old map style are incompatible with the new version, so the CT map must be
// destroyed and recreated during upgrade. By removing the old map location
// from the filesystem, we ensure that the next time that the endpoint is
// regenerated, it will recreate a new CT map with the new properties.
//
// Note that if an existing BPF program refers to the map at the canonical
// paths (as fetched via the getMapPathsToKeySize() call below), then that BPF
// program will continue to operate on the old map, even once the map is
// removed from the filesystem. The old map will only be completely cleaned up
// once all referenced to the map are cleared - that is, all BPF programs which
// refer to the old map and removed/reloaded.
func DeleteIfUpgradeNeeded(e CtEndpoint) {
	// No need to check LRU hashmap support to delete the map.
	for _, newMap := range maps(e, true, true, true) {
		path, err := newMap.Path()
		if err != nil {
			log.WithError(err).Warning("Failed to get path for CT map")
			continue
		}
		scopedLog := log.WithField(logfields.Path, path)
		oldMap, err := bpf.OpenMap(path)
		if err != nil {
			scopedLog.WithError(err).Debug("Couldn't open CT map for upgrade")
			continue
		}
		if oldMap.CheckAndUpgrade(&newMap.Map.MapInfo) {
			scopedLog.Warning("CT Map upgraded, expect brief disruption of ongoing connections")
		}
		oldMap.Close()
	}
}

// maps returns all connecting tracking maps associated with endpoint 'e' (or
// the global maps if 'e' is nil).
func maps(e CtEndpoint, ipv4, ipv6, lru bool) []*Map {
	result := make([]*Map, 0, mapCount)
	if e == nil {
		if ipv4 {
			result = append(result, newMap(MapNameTCP4Global, MapTypeIPv4TCPGlobal, lru))
			result = append(result, newMap(MapNameAny4Global, MapTypeIPv4AnyGlobal, lru))
		}
		if ipv6 {
			result = append(result, newMap(MapNameTCP6Global, MapTypeIPv6TCPGlobal, lru))
			result = append(result, newMap(MapNameAny6Global, MapTypeIPv6AnyGlobal, lru))
		}
	} else {
		if ipv4 {
			result = append(result, newMap(bpf.LocalMapName(MapNameTCP4, uint16(e.GetID())),
				MapTypeIPv4TCPLocal, lru))
			result = append(result, newMap(bpf.LocalMapName(MapNameAny4, uint16(e.GetID())),
				MapTypeIPv4AnyLocal, lru))
		}
		if ipv6 {
			result = append(result, newMap(bpf.LocalMapName(MapNameTCP6, uint16(e.GetID())),
				MapTypeIPv6TCPLocal, lru))
			result = append(result, newMap(bpf.LocalMapName(MapNameAny6, uint16(e.GetID())),
				MapTypeIPv6AnyLocal, lru))
		}
	}
	return result
}

// LocalMaps returns a slice of CT maps for the endpoint, which are local to
// the endpoint and not shared with other endpoints. If ipv4 or ipv6 are false,
// the maps for that protocol will not be returned.
//
// The returned maps are not yet opened.
func LocalMaps(e CtEndpoint, ipv4, ipv6, lru bool) []*Map {
	return maps(e, ipv4, ipv6, lru)
}

// GlobalMaps returns a slice of CT maps that are used globally by all
// endpoints that are not otherwise configured to use their own local maps.
// If ipv4 or ipv6 are false, the maps for that protocol will not be returned.
//
// The returned maps are not yet opened.
func GlobalMaps(ipv4, ipv6, lru bool) []*Map {
	return maps(nil, ipv4, ipv6, lru)
}

// NameIsGlobal returns true if the specified filename (basename) denotes a
// global conntrack map.
func NameIsGlobal(filename string) bool {
	switch filename {
	case MapNameTCP4Global, MapNameAny4Global, MapNameTCP6Global, MapNameAny6Global:
		return true
	}
	return false
}

// WriteBPFMacros writes the map names for conntrack maps into the specified
// writer, defining usage of the global map or local maps depending on whether
// the specified CtEndpoint is nil.
func WriteBPFMacros(fw io.Writer, e CtEndpoint) {
	var mapEntriesTCP, mapEntriesAny int
	// We don't need to check for LRU hashmap support
	// since we're not using the map type.
	info := getMapInfo(true)
	for _, m := range maps(e, true, true, true) {
		fmt.Fprintf(fw, "#define %s %s\n", m.define, m.Name())
		if m.mapType.isTCP() {
			mapEntriesTCP = info[m.mapType].maxEntries
		} else {
			mapEntriesAny = info[m.mapType].maxEntries
		}
	}
	fmt.Fprintf(fw, "#define CT_MAP_SIZE_TCP %d\n", mapEntriesTCP)
	fmt.Fprintf(fw, "#define CT_MAP_SIZE_ANY %d\n", mapEntriesAny)
}

// Exists returns false if the CT maps for the specified endpoint (or global
// maps if nil) are not pinned to the filesystem, or true if they exist or
// an internal error occurs.
func Exists(e CtEndpoint, ipv4, ipv6 bool) bool {
	result := true
	// We don't need to check LRU hashmap support
	// to check that the maps exist.
	for _, m := range maps(e, ipv4, ipv6, true) {
		path, err := m.Path()
		if err != nil {
			// Catch this error early
			return true
		}
		if _, err = os.Stat(path); os.IsNotExist(err) {
			result = false
		}
	}

	return result
}

var cachedGCInterval time.Duration

// GetInterval returns the interval adjusted based on the deletion ratio of the
// last run
func GetInterval(mapType bpf.MapType, maxDeleteRatio float64) (interval time.Duration) {
	if val := option.Config.ConntrackGCInterval; val != time.Duration(0) {
		interval = val
		return
	}

	if interval = cachedGCInterval; interval == time.Duration(0) {
		interval = defaults.ConntrackGCStartingInterval
	}

	return calculateInterval(mapType, interval, maxDeleteRatio)
}

func calculateInterval(mapType bpf.MapType, prevInterval time.Duration, maxDeleteRatio float64) (interval time.Duration) {
	interval = prevInterval

	if maxDeleteRatio == 0.0 {
		return
	}

	switch {
	case maxDeleteRatio > 0.25:
		if maxDeleteRatio > 0.9 {
			maxDeleteRatio = 0.9
		}
		// 25%..90% => 1.3x..10x shorter
		interval = time.Duration(float64(interval) * (1.0 - maxDeleteRatio)).Round(time.Second)

		if interval < defaults.ConntrackGCMinInterval {
			interval = defaults.ConntrackGCMinInterval
		}

	case maxDeleteRatio < 0.05:
		// When less than 5% of entries were deleted, increase the
		// interval. Use a simple 1.5x multiplier to start growing slowly
		// as a new node may not be seeing workloads yet and thus the
		// scan will return a low deletion ratio at first.
		interval = time.Duration(float64(interval) * 1.5).Round(time.Second)

		switch mapType {
		case bpf.MapTypeLRUHash:
			if interval > defaults.ConntrackGCMaxLRUInterval {
				interval = defaults.ConntrackGCMaxLRUInterval
			}
		default:
			if interval > defaults.ConntrackGCMaxInterval {
				interval = defaults.ConntrackGCMaxInterval
			}
		}
	}

	if interval != prevInterval {
		log.WithFields(logrus.Fields{
			"newInterval": interval,
			"deleteRatio": maxDeleteRatio,
		}).Info("Conntrack garbage collector interval recalculated")
	}

	cachedGCInterval = interval

	return
}
