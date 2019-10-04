// Copyright 2016-2019 Authors of Cilium
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

	mapInfo = make(map[MapType]mapAttributes)
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

// InitMapInfo builds the information about different CT maps for the
// combination of L3/L4 protocols, using the specified limits on TCP vs non-TCP
// maps.
func InitMapInfo(tcpMaxEntries, anyMaxEntries int, v4, v6 bool) {
	mapInfo = make(map[MapType]mapAttributes)

	global4Map, global6Map := nat.GlobalMaps(v4, v6)

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

func init() {
	InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true)
}

// CtEndpoint represents an endpoint for the functions required to manage
// conntrack maps for the endpoint.
type CtEndpoint interface {
	GetID() uint64
}

// Map represents an instance of a BPF connection tracking map.
type Map struct {
	bpf.Map

	mapType              MapType
	cachedGCInterval     time.Duration
	entryMinTimeoutFixed bool
	NextWakeup           uint32
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
}

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

// NewMap creates a new CT map of the specified type with the specified name.
func NewMap(mapName string, mapType MapType, mapTimeoutFixed bool) *Map {
	result := &Map{
		Map: *bpf.NewMap(mapName,
			bpf.MapTypeLRUHash,
			mapInfo[mapType].mapKey,
			mapInfo[mapType].keySize,
			mapInfo[mapType].mapValue,
			mapInfo[mapType].valueSize,
			mapInfo[mapType].maxEntries,
			0, 0,
			mapInfo[mapType].parser,
		),
		mapType:              mapType,
		define:               mapInfo[mapType].bpfDefine,
		entryMinTimeoutFixed: mapTimeoutFixed,
	}
	return result
}

// Time to live is placed into stats.DyingEntries such
// that later on we can derive a heuristic when next to
// invoke GC.
//
// Timespan:           ->  Bucket:
//
//      1s ...     1s      0
//      2s ...     3s      1
//      4s ...     7s      2
//      8s ...    15s      3
//     16s ...    31s      4
//     32s ...    63s      5
//     64s ...   127s      6
//    128s ...   255s      7
//    256s ...   511s      8
//    512s ...  1023s      9
//   1024s ...  2047s     10
//   2048s ...  4095s     11
//   4096s ...  8191s     12
//   8192s ... 16383s     13
//  16384s ... 32767s     14
//  32768s ... 65535s     15
//
func collectAliveStats(entry *CtEntry, stats *gcStats, currTime uint32) {
	stats.AliveEntries++
	deadline := entry.Lifetime - currTime
	idx := uint(math.Log2(float64(deadline)))
	if idx >= uint(len(stats.DyingEntries)) {
		idx = uint(len(stats.DyingEntries)) - 1
	}
	stats.DyingEntries[idx]++
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
	natMap := mapInfo[m.mapType].natMap
	stats := statStartGc(m)
	stats.CurrTime = filter.Time
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
			action := filter.doFiltering(currentKey6Global.DestAddr.IP(), currentKey6Global.SourceAddr.IP(), currentKey6Global.SourcePort,
				uint8(currentKey6Global.NextHeader), currentKey6Global.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry6(m, currentKey6Global, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey6Global.String()).Error("Unable to delete CT entry")
				} else {
					stats.Deleted++
				}
			default:
				collectAliveStats(entry, &stats, filter.Time)
			}
		case *CtKey6:
			currentKey6 := obj
			// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
			// the destination of the packet received, therefore it's the packet's
			// destination IP
			action := filter.doFiltering(currentKey6.DestAddr.IP(), currentKey6.SourceAddr.IP(), currentKey6.SourcePort,
				uint8(currentKey6.NextHeader), currentKey6.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry6(m, currentKey6, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey6.String()).Error("Unable to delete CT entry")
				} else {
					stats.Deleted++
				}
			default:
				collectAliveStats(entry, &stats, filter.Time)
			}
		default:
			log.Warningf("Encountered unknown type while scanning conntrack table: %v", reflect.TypeOf(key))
		}
	}
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)

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
	natMap := mapInfo[m.mapType].natMap
	stats := statStartGc(m)
	stats.CurrTime = filter.Time
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
			action := filter.doFiltering(currentKey4Global.DestAddr.IP(), currentKey4Global.SourceAddr.IP(), currentKey4Global.SourcePort,
				uint8(currentKey4Global.NextHeader), currentKey4Global.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry4(m, currentKey4Global, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey4Global.String()).Error("Unable to delete CT entry")
				} else {
					stats.Deleted++
				}
			default:
				collectAliveStats(entry, &stats, filter.Time)
			}
		case *CtKey4:
			currentKey4 := obj
			// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
			// the destination of the packet received, therefore it's the packet's
			// destination IP
			action := filter.doFiltering(currentKey4.DestAddr.IP(), currentKey4.SourceAddr.IP(), currentKey4.SourcePort,
				uint8(currentKey4.NextHeader), currentKey4.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry4(m, currentKey4, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey4.String()).Error("Unable to delete CT entry")
				} else {
					stats.Deleted++
				}
			default:
				collectAliveStats(entry, &stats, filter.Time)
			}
		default:
			log.Warningf("Encountered unknown type while scanning conntrack table: %v", reflect.TypeOf(key))
		}
	}
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)

	return stats
}

func (f *GCFilter) doFiltering(srcIP net.IP, dstIP net.IP, dstPort uint16, nextHdr, flags uint8, entry *CtEntry) (action int) {
	if f.RemoveExpired && entry.Lifetime <= f.Time {
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

	return noAction
}

func doGC(m *Map, filter *GCFilter) gcStats {
	if m.mapType.isIPv6() {
		return doGC6(m, filter)
	} else if m.mapType.isIPv4() {
		return doGC4(m, filter)
	}
	log.Fatalf("Unsupported ct map type: %s", m.mapType.String())
	return gcStats{}
}

// GC runs garbage collection for map m with name mapType with the given filter.
// It returns how many items were deleted from m.
func GC(m *Map, filter *GCFilter) gcStats {
	if filter.RemoveExpired && filter.Time == 0 {
		t, _ := bpf.GetMtime()
		tsec := t / 1000000000
		filter.Time = uint32(tsec)
	}

	return doGC(m, filter)
}

// Flush runs garbage collection for map m with the name mapType, deleting all
// entries. The specified map must be already opened using bpf.OpenMap().
func (m *Map) Flush() int {
	return int(doGC(m, &GCFilter{
		RemoveExpired: true,
		Time:          MaxTime,
	}).Deleted)
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
	for _, newMap := range maps(e, true, true) {
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
func maps(e CtEndpoint, ipv4, ipv6 bool) []*Map {
	result := make([]*Map, 0, mapCount)
	if e == nil {
		if ipv4 {
			result = append(result, NewMap(MapNameTCP4Global, MapTypeIPv4TCPGlobal, false))
			result = append(result, NewMap(MapNameAny4Global, MapTypeIPv4AnyGlobal, true))
		}
		if ipv6 {
			result = append(result, NewMap(MapNameTCP6Global, MapTypeIPv6TCPGlobal, false))
			result = append(result, NewMap(MapNameAny6Global, MapTypeIPv6AnyGlobal, true))
		}
	} else {
		if ipv4 {
			result = append(result, NewMap(bpf.LocalMapName(MapNameTCP4, uint16(e.GetID())),
				MapTypeIPv4TCPLocal, false))
			result = append(result, NewMap(bpf.LocalMapName(MapNameAny4, uint16(e.GetID())),
				MapTypeIPv4AnyLocal, true))
		}
		if ipv6 {
			result = append(result, NewMap(bpf.LocalMapName(MapNameTCP6, uint16(e.GetID())),
				MapTypeIPv6TCPLocal, false))
			result = append(result, NewMap(bpf.LocalMapName(MapNameAny6, uint16(e.GetID())),
				MapTypeIPv6AnyLocal, true))
		}
	}
	return result
}

// LocalMaps returns a slice of CT maps for the endpoint, which are local to
// the endpoint and not shared with other endpoints. If ipv4 or ipv6 are false,
// the maps for that protocol will not be returned.
//
// The returned maps are not yet opened.
func LocalMaps(e CtEndpoint, ipv4, ipv6 bool) []*Map {
	return maps(e, ipv4, ipv6)
}

var once sync.Once
var globalMaps []*Map

// GlobalMaps returns a slice of CT maps that are used globally by all
// endpoints that are not otherwise configured to use their own local maps.
// If ipv4 or ipv6 are false, the maps for that protocol will not be returned.
//
// The returned maps are not yet opened.
func GlobalMaps(ipv4, ipv6 bool) []*Map {
	once.Do(func() {
		globalMaps = maps(nil, ipv4, ipv6)
	})
	return globalMaps
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
	for _, m := range maps(e, true, true) {
		fmt.Fprintf(fw, "#define %s %s\n", m.define, m.Name())
		if m.mapType.isTCP() {
			mapEntriesTCP = mapInfo[m.mapType].maxEntries
		} else {
			mapEntriesAny = mapInfo[m.mapType].maxEntries
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
	for _, m := range maps(e, ipv4, ipv6) {
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

func capToMaxInterval(m *Map, interval time.Duration) time.Duration {
	switch m.MapInfo.MapType {
	case bpf.MapTypeLRUHash:
		if interval > defaults.ConntrackGCMaxLRUInterval {
			return defaults.ConntrackGCMaxLRUInterval
		}
	default:
		if interval > defaults.ConntrackGCMaxInterval {
			return defaults.ConntrackGCMaxInterval
		}
	}
	return interval
}

// InitInterval returns the default interval which is then further adjusted
// down through GetInterval in the GC run
func InitInterval() (interval time.Duration) {
	if val := option.Config.ConntrackGCInterval; val != time.Duration(0) {
		interval = val
		return
	}

	return defaults.ConntrackGCMaxLRUInterval
}

// GetInterval returns the next wakeup interval for the GC
func GetInterval(m *Map, stats gcStats) (interval time.Duration) {
	if val := option.Config.ConntrackGCInterval; val != time.Duration(0) {
		interval = val
		return
	}

	if interval = m.cachedGCInterval; interval == time.Duration(0) {
		interval = defaults.ConntrackGCStartingInterval
	}

	return calculateInterval(m, interval, stats)
}

func thresholdGC() float64 {
	switch option.Config.ConntrackGCProfile {
	case option.ConntrackGCProfileAggressive:
		return 0.01
	case option.ConntrackGCProfileNormal:
		return 0.3
	case option.ConntrackGCProfileLazy:
		fallthrough
	default:
		return 0.6
	}
}

func calculateInterval(m *Map, prevInterval time.Duration, stats gcStats) (interval time.Duration) {
	interval = prevInterval
	threshold := thresholdGC()
	thresholdHit := false
	sum := uint32(0)

	// Step 1:
	//
	// We accumulate all entries in the time buckets until they surpass
	// our GC profile threshold. In the /best/ case, this means the next
	// GC run for this map would be able to clean up all entries under
	// this threshold as they have expired.
	//
	for i := 0; i < len(stats.DyingEntries); i++ {
		sum += stats.DyingEntries[i]
		if float64(sum)/float64(m.MapInfo.MaxEntries) >= threshold {
			interval = (1 << uint32(i)) * time.Second
			thresholdHit = true
			break
		}
	}

	// Step 2:
	//
	// There were not enough entries in the CT table to reach beyond the
	// given threshold. We can be more lazy next time, therefore increase
	// the previous interval by a 1.5 multiplier and cap at the default
	// maximum GC interval.
	//
	if interval == prevInterval && !thresholdHit {
		interval = capToMaxInterval(m, time.Duration(float64(interval)*1.5).Round(time.Second))
	}

	// Step 3:
	//
	// For the cilium_ct_any{4,6}* maps, we have the guarantee that there
	// are no "dynamic" timeouts compared to the TCP connection teardown,
	// meaning the minimum timeout is always fixed from this point onwards
	// and therefore it does not make any sense to wake up at an earlier
	// point in time. When in aggressive profile for the TCP CT tables, we
	// cannot wait for that long as there may be many short-lived connections
	// and NAT needs faster recycle.
	//
	if !m.entryMinTimeoutFixed {
		if option.Config.ConntrackGCProfile == option.ConntrackGCProfileAggressive {
			intervalMax := (1 << 5) * time.Second
			if interval > intervalMax {
				interval = intervalMax
			}
		}
	}

	m.cachedGCInterval = interval
	m.NextWakeup = stats.CurrTime + uint32(interval.Seconds())

	if interval != prevInterval {
		path, _ := m.Path()
		log.WithFields(logrus.Fields{
			"Path":        path,
			"Alive":       stats.AliveEntries,
			"Deleted":     stats.Deleted,
			"IntervalOld": prevInterval,
			"IntervalNew": interval,
		}).Info("Conntrack garbage collector interval recalculated")
	}

	return
}
