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

package ctmap

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"path"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
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

	mapInfo = map[MapType]struct {
		keySize    int
		maxEntries int
		parser     bpf.DumpParser
		bpfDefine  string
	}{
		MapTypeIPv4Local: {
			keySize:    int(unsafe.Sizeof(CtKey4{})),
			maxEntries: MapNumEntriesLocal,
			parser:     ct4DumpParser,
			bpfDefine:  "CT_MAP4",
		},
		MapTypeIPv6Local: {
			keySize:    int(unsafe.Sizeof(CtKey6{})),
			maxEntries: MapNumEntriesLocal,
			parser:     ct6DumpParser,
			bpfDefine:  "CT_MAP6",
		},
		MapTypeIPv4Global: {
			keySize:    int(unsafe.Sizeof(CtKey4{})),
			maxEntries: MapNumEntriesGlobal,
			parser:     ct4DumpParser,
			bpfDefine:  "CT_MAP4",
		},
		MapTypeIPv6Global: {
			keySize:    int(unsafe.Sizeof(CtKey6{})),
			maxEntries: MapNumEntriesGlobal,
			parser:     ct6DumpParser,
			bpfDefine:  "CT_MAP6",
		},
	}
)

const (
	// MapTypeIPv4Local and friends are MapTypes which correspond to a
	// combination of the following attributes:
	// * IPv4 or IPv6;
	// * Local (endpoint-specific) or global (endpoint-oblivious).
	MapTypeIPv4Local = iota
	MapTypeIPv6Local
	MapTypeIPv4Global
	MapTypeIPv6Global

	// mapCount counts the maximum number of CT maps that one endpoint may
	// access at once.
	mapCount = 2

	MapName6       = "cilium_ct6_"
	MapName4       = "cilium_ct4_"
	MapName6Global = MapName6 + "global"
	MapName4Global = MapName4 + "global"

	MapNumEntriesLocal  = 64000
	MapNumEntriesGlobal = 1000000

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

// CtEndpoint represents an endpoint for the functions required to manage
// conntrack maps for the endpoint.
type CtEndpoint interface {
	StringID() string
}

// MapType is a type of connection tracking map.
type MapType int

// String renders the map type into a user-readable string.
func (m MapType) String() string {
	switch m {
	case MapTypeIPv4Local:
		return "Local IPv4 CT map"
	case MapTypeIPv6Local:
		return "Local IPv6 CT map"
	case MapTypeIPv4Global:
		return "Global IPv4 CT map"
	case MapTypeIPv6Global:
		return "Global IPv6 CT map"
	}
	return fmt.Sprintf("Unknown (%d)", int(m))
}

// Map represents an instance of a BPF connection tracking map.
type Map struct {
	bpf.Map

	mapType MapType
	// define maps to the macro used in the datapath portion for the map
	// name, for example 'CT_MAP4'.
	define string
}

// CtKey is the interface describing keys to the conntrack maps.
type CtKey interface {
	bpf.MapKey

	// ToNetwork converts fields to network byte order.
	ToNetwork() CtKey

	// ToHost converts fields to host byte order.
	ToHost() CtKey

	// Dumps contents of key to buffer. Returns true if successful.
	Dump(buffer *bytes.Buffer) bool
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
		key := k.(CtKey)
		if !key.ToHost().Dump(&buffer) {
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
	k, v := CtKey4Global{}, CtEntry{}

	if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
		return nil, nil, err
	}
	return &k, &v, nil
}

func ct6DumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	k, v := CtKey6Global{}, CtEntry{}

	if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
		return nil, nil, err
	}
	return &k, &v, nil
}

// NewMap creates a new CT map of the specified type with the specified name.
func NewMap(mapName string, mapType MapType) *Map {
	result := &Map{
		Map: *bpf.NewMap(mapName,
			bpf.GetLRUMapType(),
			mapInfo[mapType].keySize,
			int(unsafe.Sizeof(CtEntry{})),
			mapInfo[mapType].maxEntries,
			0,
			mapInfo[mapType].parser,
		),
		mapType: mapType,
		define:  mapInfo[mapType].bpfDefine,
	}
	return result
}

// doGC6 iterates through a CTv6 map and drops entries based on the given
// filter.
func doGC6(m *bpf.Map, filter *GCFilter) gcStats {
	var prevKey, currentKey, nextKey CtKey6Global

	stats := statStartGc(m, gcFamilyIPv6)
	defer stats.finish()

	// prevKey is initially invalid, causing GetNextKey to return the first key in the map as currentKey.
	prevKeyValid := false
	err := m.GetNextKey(&prevKey, &currentKey)
	if err != nil {
		// Map is empty, nothing to clean up.
		stats.Completed = true
		return stats
	}

	for stats.Lookup = 1; stats.Lookup <= stats.MaxEntries; stats.Lookup++ {
		// currentKey was returned by GetNextKey() so we know it existed in the map, but it may have been
		// deleted by a concurrent map operation. If currentKey is no longer in the map, nextKey will be
		// the first key in the map again. Use the nextKey only if we still find currentKey in the Lookup()
		// after the GetNextKey() call, this way we know nextKey is NOT the first key in the map.
		nextKeyValid := m.GetNextKey(&currentKey, &nextKey)
		entryMap, err := m.Lookup(&currentKey)
		if err != nil {
			stats.LookupFailed++

			// Restarting from a invalid key starts the iteration again from the beginning.
			// If we have a previously found key, try to restart from there instead
			if prevKeyValid {
				currentKey = prevKey
				// Restart from a given previous key only once, otherwise if the prevKey is
				// concurrently deleted we might loop forever trying to look it up.
				prevKeyValid = false
				stats.KeyFallback++
			} else {
				// Depending on exactly when currentKey was deleted from the map, nextKey may be the actual
				// keyelement after the deleted one, or the first element in the map.
				currentKey = nextKey
				stats.Interrupted++
			}
			continue
		}

		entry := entryMap.(*CtEntry)

		// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
		// the destination of the packet received, therefore it's the packet's
		// destination IP
		action := filter.doFiltering(currentKey.DestAddr.IP(), currentKey.SourceAddr.IP(), currentKey.SourcePort,
			uint8(currentKey.NextHeader), currentKey.Flags, entry)

		switch action {
		case deleteEntry:
			err := m.Delete(&currentKey)
			if err != nil {
				log.WithError(err).Errorf("Unable to delete CT entry %s", currentKey.String())
			} else {
				stats.deleted++
			}
		default:
			stats.aliveEntries++
		}

		if nextKeyValid != nil {
			stats.Completed = true
			break
		}
		// remember the last found key
		prevKey = currentKey
		prevKeyValid = true
		// continue from the next key
		currentKey = nextKey
	}

	return stats
}

// doGC4 iterates through a CTv4 map and drops entries based on the given
// filter.
func doGC4(m *bpf.Map, filter *GCFilter) gcStats {
	var prevKey, currentKey, nextKey CtKey4Global

	stats := statStartGc(m, gcFamilyIPv4)
	defer stats.finish()

	// prevKey is initially invalid, causing GetNextKey to return the first key in the map as currentKey.
	prevKeyValid := false
	err := m.GetNextKey(&prevKey, &currentKey)
	if err != nil {
		// Map is empty, nothing to clean up.
		stats.Completed = true
		return stats
	}

	for stats.Lookup = 1; stats.Lookup <= stats.MaxEntries; stats.Lookup++ {
		// currentKey was returned by GetNextKey() so we know it existed in the map, but it may have been
		// deleted by a concurrent map operation. If currentKey is no longer in the map, nextKey will be
		// the first key in the map again. Use the nextKey only if we still find currentKey in the Lookup()
		// after the GetNextKey() call, this way we know nextKey is NOT the first key in the map.
		nextKeyValid := m.GetNextKey(&currentKey, &nextKey)
		entryMap, err := m.Lookup(&currentKey)
		if err != nil {
			stats.LookupFailed++

			// Restarting from a invalid key starts the iteration again from the beginning.
			// If we have a previously found key, try to restart from there instead
			if prevKeyValid {
				currentKey = prevKey
				// Restart from a given previous key only once, otherwise if the prevKey is
				// concurrently deleted we might loop forever trying to look it up.
				prevKeyValid = false
				stats.KeyFallback++
			} else {
				// Depending on exactly when currentKey was deleted from the map, nextKey may be the actual
				// keyelement after the deleted one, or the first element in the map.
				currentKey = nextKey
				stats.Interrupted++
			}
			continue
		}

		entry := entryMap.(*CtEntry)

		// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
		// the destination of the packet received, therefore it's the packet's
		// destination IP
		action := filter.doFiltering(currentKey.DestAddr.IP(), currentKey.SourceAddr.IP(), currentKey.SourcePort,
			uint8(currentKey.NextHeader), currentKey.Flags, entry)

		switch action {
		case deleteEntry:
			err := m.Delete(&currentKey)
			if err != nil {
				log.WithError(err).Errorf("Unable to delete CT entry %s", currentKey.String())
			} else {
				stats.deleted++
			}
		default:
			stats.aliveEntries++
		}

		if nextKeyValid != nil {
			stats.Completed = true
			break
		}
		// remember the last found key
		prevKey = currentKey
		prevKeyValid = true
		// continue from the next key
		currentKey = nextKey
	}

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
	switch m.mapType {
	case MapTypeIPv6Local, MapTypeIPv6Global:
		return int(doGC6(&m.Map, filter).deleted)
	case MapTypeIPv4Local, MapTypeIPv4Global:
		return int(doGC4(&m.Map, filter).deleted)
	default:
		log.Fatalf("Unsupported ct map type: %s", m.mapType.String())
	}

	return 0
}

// GC runs garbage collection for map m with name mapType with the given filter.
// It returns how many items were deleted from m.
func GC(m *Map, filter *GCFilter) int {
	if filter.RemoveExpired {
		// If LRUHashtable, no need to garbage collect as LRUHashtable cleans itself up.
		// FIXME: GH-3239 LRU logic is not handling timeouts gracefully enough
		// if m.MapInfo.MapType == bpf.MapTypeLRUHash {
		// 	return 0
		// }
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
			scopedLog.Info("CT Map upgraded, expect brief disruption of ongoing connections")
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
			result = append(result, NewMap(MapName4Global, MapTypeIPv4Global))
		}
		if ipv6 {
			result = append(result, NewMap(MapName6Global, MapTypeIPv6Global))
		}
	} else {
		if ipv4 {
			result = append(result, NewMap(MapName4+e.StringID(), MapTypeIPv4Local))
		}
		if ipv6 {
			result = append(result, NewMap(MapName6+e.StringID(), MapTypeIPv6Local))
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
// If ipv6 or ipv6 are false, the maps for that protocol will not be returned.
//
// The returned maps are not yet opened.
func GlobalMaps(ipv4, ipv6 bool) []*Map {
	return maps(nil, ipv4, ipv6)
}

// WriteBPFMacros writes the map names for conntrack maps into the specified
// writer, defining usage of the global map or local maps depending on whether
// the specified CtEndpoint is nil.
func WriteBPFMacros(fw io.Writer, e CtEndpoint) {
	if e == nil {
		fmt.Fprintf(fw, "#define CT_MAP_SIZE %d\n", MapNumEntriesGlobal)
	} else {
		fmt.Fprintf(fw, "#define CT_MAP_SIZE %d\n", MapNumEntriesLocal)
	}
	for _, m := range maps(e, true, true) {
		filepath, err := m.Path()
		if err != nil {
			log.WithError(err).Warningf("Cannot define BPF macro for %s", m.define)
			continue
		}
		fmt.Fprintf(fw, "#define %s %s\n", m.define, path.Base(filepath))
	}
}
