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
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
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

type mapAttributes struct {
	keySize    int
	maxEntries int
	parser     bpf.DumpParser
	bpfDefine  string
	natMap     *nat.Map
}

func setupMapInfo(mapType MapType, define string, keySize, maxEntries int, parser bpf.DumpParser, nat *nat.Map) {
	mapInfo[mapType] = mapAttributes{
		bpfDefine:  define,
		keySize:    keySize,
		maxEntries: maxEntries,
		parser:     parser,
		natMap:     nat,
	}
}

// InitMapInfo builds the information about different CT maps for the
// combination of L3/L4 protocols, using the specified limits on TCP vs non-TCP
// maps.
func InitMapInfo(tcpMaxEntries, anyMaxEntries int) {
	mapInfo = make(map[MapType]mapAttributes)
	natMaps := nat.GlobalMaps(true, true)
	natV4 := natMaps[0]
	natV6 := natMaps[1]

	mapType := MapTypeIPv4TCPLocal
	for _, maxEntries := range []int{MapNumEntriesLocal, tcpMaxEntries} {
		setupMapInfo(MapType(mapType), "CT_MAP_TCP4",
			int(unsafe.Sizeof(tuple.TupleKey4{})), maxEntries,
			ct4DumpParser, natV4)
		mapType++
		setupMapInfo(MapType(mapType), "CT_MAP_TCP6",
			int(unsafe.Sizeof(tuple.TupleKey6{})), maxEntries,
			ct6DumpParser, natV6)
		mapType++
	}
	for _, maxEntries := range []int{MapNumEntriesLocal, anyMaxEntries} {
		setupMapInfo(MapType(mapType), "CT_MAP_ANY4",
			int(unsafe.Sizeof(tuple.TupleKey4{})), maxEntries,
			ct4DumpParser, natV4)
		mapType++
		setupMapInfo(MapType(mapType), "CT_MAP_ANY6",
			int(unsafe.Sizeof(tuple.TupleKey6{})), maxEntries,
			ct6DumpParser, natV6)
		mapType++
	}
}

func init() {
	InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault)
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
}

// ToString iterates through Map m and writes the values of the ct entries in m
// to a string.
func (m *Map) DumpEntries() (string, error) {
	var buffer bytes.Buffer

	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(tuple.TupleKey)
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

func ct4DumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	k, v := tuple.TupleKey4Global{}, CtEntry{}

	if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
		return nil, nil, err
	}
	return &k, &v, nil
}

func ct6DumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	k, v := tuple.TupleKey6Global{}, CtEntry{}

	if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
		return nil, nil, err
	}
	return &k, &v, nil
}

// NewMap creates a new CT map of the specified type with the specified name.
func NewMap(mapName string, mapType MapType) *Map {
	result := &Map{
		Map: *bpf.NewMap(mapName,
			bpf.MapTypeLRUHash,
			mapInfo[mapType].keySize,
			int(unsafe.Sizeof(CtEntry{})),
			mapInfo[mapType].maxEntries,
			0, 0,
			mapInfo[mapType].parser,
		),
		mapType: mapType,
		define:  mapInfo[mapType].bpfDefine,
	}
	return result
}

func purgeCtEntry6(m *Map, key *tuple.TupleKey6Global, natMap *nat.Map) error {
	err := m.Delete(key)
	if err == nil && natMap != nil {
		natMap.DeleteMapping(key)
	}
	return err
}

// doGC6 iterates through a CTv6 map and drops entries based on the given
// filter.
func doGC6(m *Map, filter *GCFilter) gcStats {
	natMap := mapInfo[m.mapType].natMap
	stats := statStartGc(m)
	defer stats.finish()

	err := natMap.Open()
	if err == nil {
		defer natMap.Close()
	} else {
		natMap = nil
	}

	filterCallback := func(key bpf.MapKey, value bpf.MapValue) {
		currentKey := key.(*tuple.TupleKey6Global)
		entry := value.(*CtEntry)

		// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
		// the destination of the packet received, therefore it's the packet's
		// destination IP
		action := filter.doFiltering(currentKey.DestAddr.IP(), currentKey.SourceAddr.IP(), currentKey.SourcePort,
			uint8(currentKey.NextHeader), currentKey.Flags, entry)

		switch action {
		case deleteEntry:
			err := purgeCtEntry6(m, currentKey, natMap)
			if err != nil {
				log.WithError(err).WithField(logfields.Key, currentKey.String()).Error("Unable to delete CT entry")
			} else {
				stats.deleted++
			}
		default:
			stats.aliveEntries++
		}
	}
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)

	return stats
}

func purgeCtEntry4(m *Map, key *tuple.TupleKey4Global, natMap *nat.Map) error {
	err := m.Delete(key)
	if err == nil && natMap != nil {
		natMap.DeleteMapping(key)
	}
	return err
}

// doGC4 iterates through a CTv4 map and drops entries based on the given
// filter.
func doGC4(m *Map, filter *GCFilter) gcStats {
	natMap := mapInfo[m.mapType].natMap
	stats := statStartGc(m)
	defer stats.finish()

	err := natMap.Open()
	if err == nil {
		defer natMap.Close()
	} else {
		natMap = nil
	}

	filterCallback := func(key bpf.MapKey, value bpf.MapValue) {
		currentKey := key.(*tuple.TupleKey4Global)
		entry := value.(*CtEntry)

		// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
		// the destination of the packet received, therefore it's the packet's
		// destination IP
		action := filter.doFiltering(currentKey.DestAddr.IP(), currentKey.SourceAddr.IP(), currentKey.SourcePort,
			uint8(currentKey.NextHeader), currentKey.Flags, entry)

		switch action {
		case deleteEntry:
			err := purgeCtEntry4(m, currentKey, natMap)
			if err != nil {
				log.WithError(err).WithField(logfields.Key, currentKey.String()).Error("Unable to delete CT entry")
			} else {
				stats.deleted++
			}
		default:
			stats.aliveEntries++
		}
	}
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)

	return stats
}

func (f *GCFilter) doFiltering(srcIP net.IP, dstIP net.IP, dstPort uint16, nextHdr, flags uint8, entry *CtEntry) (action int) {
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
			result = append(result, NewMap(MapNameTCP4Global, MapTypeIPv4TCPGlobal))
			result = append(result, NewMap(MapNameAny4Global, MapTypeIPv4AnyGlobal))
		}
		if ipv6 {
			result = append(result, NewMap(MapNameTCP6Global, MapTypeIPv6TCPGlobal))
			result = append(result, NewMap(MapNameAny6Global, MapTypeIPv6AnyGlobal))
		}
	} else {
		if ipv4 {
			result = append(result, NewMap(bpf.LocalMapName(MapNameTCP4, uint16(e.GetID())),
				MapTypeIPv4TCPLocal))
			result = append(result, NewMap(bpf.LocalMapName(MapNameAny4, uint16(e.GetID())),
				MapTypeIPv4AnyLocal))
		}
		if ipv6 {
			result = append(result, NewMap(bpf.LocalMapName(MapNameTCP6, uint16(e.GetID())),
				MapTypeIPv6TCPLocal))
			result = append(result, NewMap(bpf.LocalMapName(MapNameAny6, uint16(e.GetID())),
				MapTypeIPv6AnyLocal))
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

// GlobalMaps returns a slice of CT maps that are used globally by all
// endpoints that are not otherwise configured to use their own local maps.
// If ipv4 or ipv6 are false, the maps for that protocol will not be returned.
//
// The returned maps are not yet opened.
func GlobalMaps(ipv4, ipv6 bool) []*Map {
	return maps(nil, ipv4, ipv6)
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
