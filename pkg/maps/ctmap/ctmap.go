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
	"math"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
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
)

const (
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

// GetMapTypeAndPath returns the map type and path for the CT map for the
// specified endpoint. Returns the global map path if e is nil.
func GetMapTypeAndPath(e CtEndpoint, isIPv6 bool) (string, string) {
	var (
		file    string
		mapType string
	)

	// Choose whether to garbage collect the local or global conntrack map
	if e != nil {
		if isIPv6 {
			mapType = MapName6
		} else {
			mapType = MapName4
		}
		file = bpf.MapPath(mapType + e.StringID())
	} else {
		if isIPv6 {
			mapType = MapName6Global
		} else {
			mapType = MapName4Global
		}
		file = bpf.MapPath(mapType)
	}

	return mapType, file
}

func getMapPath(e CtEndpoint, isIPv6 bool) string {
	_, path := GetMapTypeAndPath(e, isIPv6)
	return path
}

// getMaps fetches all paths for conntrack maps associated with the specified
// endpoint, and returns a map from these paths to the keySize used for that
// map.
func getMapPathsToKeySize(e CtEndpoint) map[string]uint32 {
	return map[string]uint32{
		getMapPath(e, true):  uint32(unsafe.Sizeof(CtKey6{})),
		getMapPath(e, false): uint32(unsafe.Sizeof(CtKey4{})),
	}
}

type CtType int

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
func ToString(m *bpf.Map, mapName string) (string, error) {
	var buffer bytes.Buffer
	entries, err := dumpToSlice(m, mapName)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.Key.ToHost().Dump(&buffer) {
			continue
		}

		value := entry.Value
		buffer.WriteString(
			fmt.Sprintf(" expires=%d rx_packets=%d rx_bytes=%d tx_packets=%d tx_bytes=%d flags=%x revnat=%d src_sec_id=%d\n",
				value.Lifetime,
				value.RxPackets,
				value.RxBytes,
				value.TxPackets,
				value.TxBytes,
				value.Flags,
				byteorder.NetworkToHost(value.RevNAT),
				value.SourceSecurityID,
			),
		)

	}
	return buffer.String(), nil
}

// DumpToSlice iterates through map m and returns a slice mapping each key to
// its value in m.
func dumpToSlice(m *bpf.Map, mapType string) ([]CtEntryDump, error) {
	entries := []CtEntryDump{}

	switch mapType {
	case MapName6, MapName6Global:
		var key, nextKey CtKey6Global
		for {
			err := m.GetNextKey(&key, &nextKey)
			if err != nil {
				break
			}

			entry, err := m.Lookup(&nextKey)
			if err != nil {
				return nil, err
			}
			ctEntry := entry.(*CtEntry)

			nK := nextKey
			eDump := CtEntryDump{Key: &nK, Value: *ctEntry}
			entries = append(entries, eDump)

			key = nextKey
		}

	case MapName4, MapName4Global:
		var key, nextKey CtKey4Global
		for {
			err := m.GetNextKey(&key, &nextKey)
			if err != nil {
				break
			}

			entry, err := m.Lookup(&nextKey)
			if err != nil {
				return nil, err
			}
			ctEntry := entry.(*CtEntry)

			nK := nextKey
			eDump := CtEntryDump{Key: &nK, Value: *ctEntry}
			entries = append(entries, eDump)

			key = nextKey
		}
	}
	return entries, nil
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
		stats.completed = true
		return stats
	}

	for stats.count = 1; stats.count <= m.MapInfo.MaxEntries; stats.count++ {
		// currentKey was returned by GetNextKey() so we know it existed in the map, but it may have been
		// deleted by a concurrent map operation. If currentKey is no longer in the map, nextKey will be
		// the first key in the map again. Use the nextKey only if we still find currentKey in the Lookup()
		// after the GetNextKey() call, this way we know nextKey is NOT the first key in the map.
		nextKeyValid := m.GetNextKey(&currentKey, &nextKey)
		entryMap, err := m.Lookup(&currentKey)
		if err != nil {
			stats.lookupFailed++

			// Restarting from a invalid key starts the iteration again from the beginning.
			// If we have a previously found key, try to restart from there instead
			if prevKeyValid {
				currentKey = prevKey
				// Restart from a given previous key only once, otherwise if the prevKey is
				// concurrently deleted we might loop forever trying to look it up.
				prevKeyValid = false
				stats.keyFallback++
			} else {
				// Depending on exactly when currentKey was deleted from the map, nextKey may be the actual
				// keyelement after the deleted one, or the first element in the map.
				currentKey = nextKey
				stats.interrupted++
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
			stats.completed = true
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
		stats.completed = true
		return stats
	}

	for stats.count = 1; stats.count <= m.MapInfo.MaxEntries; stats.count++ {
		// currentKey was returned by GetNextKey() so we know it existed in the map, but it may have been
		// deleted by a concurrent map operation. If currentKey is no longer in the map, nextKey will be
		// the first key in the map again. Use the nextKey only if we still find currentKey in the Lookup()
		// after the GetNextKey() call, this way we know nextKey is NOT the first key in the map.
		nextKeyValid := m.GetNextKey(&currentKey, &nextKey)
		entryMap, err := m.Lookup(&currentKey)
		if err != nil {
			stats.lookupFailed++

			// Restarting from a invalid key starts the iteration again from the beginning.
			// If we have a previously found key, try to restart from there instead
			if prevKeyValid {
				currentKey = prevKey
				// Restart from a given previous key only once, otherwise if the prevKey is
				// concurrently deleted we might loop forever trying to look it up.
				prevKeyValid = false
				stats.keyFallback++
			} else {
				// Depending on exactly when currentKey was deleted from the map, nextKey may be the actual
				// keyelement after the deleted one, or the first element in the map.
				currentKey = nextKey
				stats.interrupted++
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
			stats.completed = true
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

func doGC(m *bpf.Map, mapType string, filter *GCFilter) int {
	switch mapType {
	case MapName6, MapName6Global:
		return int(doGC6(m, filter).deleted)
	case MapName4, MapName4Global:
		return int(doGC4(m, filter).deleted)
	default:
		log.Fatalf("Unsupported ct map type: %s", mapType)
	}

	return 0
}

// GC runs garbage collection for map m with name mapType with the given filter.
// It returns how many items were deleted from m.
func GC(m *bpf.Map, mapType string, filter *GCFilter) int {
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

	return doGC(m, mapType, filter)
}

// Flush runs garbage collection for map m with the name mapType, deleting all
// entries. The specified map must be already opened using bpf.OpenMap().
func Flush(m *bpf.Map, mapType string) int {
	return doGC(m, mapType, &GCFilter{
		RemoveExpired: true,
		Time:          MaxTime,
	})
}

// checkAndUpgrade determines whether the ctmap on the filesystem has different
// map properties than this version of Cilium, and if so, removes the map from
// the filesystem so that a subsequent BPF prog install will recreate it with
// the correct map properties.
//
// Returns true if the map was upgraded.
func checkAndUpgrade(m *bpf.Map, e CtEndpoint, keySize uint32) bool {
	desiredMapInfo := &bpf.MapInfo{
		MapType:   bpf.GetLRUMapType(),
		KeySize:   keySize,
		ValueSize: uint32(unsafe.Sizeof(CtEntry{})),
	}

	if e == nil {
		desiredMapInfo.MaxEntries = MapNumEntriesGlobal
	} else {
		desiredMapInfo.MaxEntries = MapNumEntriesLocal
	}

	return m.CheckAndUpgrade(desiredMapInfo)
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
	for path, keySize := range getMapPathsToKeySize(e) {
		scopedLog := log.WithField(logfields.Path, path)
		oldMap, err := bpf.OpenMap(path)
		if err != nil {
			scopedLog.WithError(err).Debug("Couldn't open CT map for upgrade")
			continue
		}
		if checkAndUpgrade(oldMap, e, keySize) {
			scopedLog.Info("CT Map upgraded, expect brief disruption of ongoing connections")
		}
		oldMap.Close()
	}
}
