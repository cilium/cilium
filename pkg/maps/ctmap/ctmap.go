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
	"github.com/cilium/cilium/pkg/metrics"
)

var (
	log = logging.DefaultLogger

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
)

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

// CtEntry represents an entry in the connection tracking table.
type CtEntry struct {
	rx_packets uint64
	rx_bytes   uint64
	tx_packets uint64
	tx_bytes   uint64
	lifetime   uint32
	flags      uint16
	// revnat is in network byte order
	revnat         uint16
	tx_flags_seen  uint8
	rx_flags_seen  uint8
	src_sec_id     uint32
	last_tx_report uint32
	last_rx_report uint32
}

// GetValuePtr returns the unsafe.Pointer for s.
func (c *CtEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(c) }

// String returns the readable format
func (c *CtEntry) String() string {
	return fmt.Sprintf("expires=%d rx_packets=%d rx_bytes=%d tx_packets=%d tx_bytes=%d flags=%x revnat=%d src_sec_id=%d\n",
		c.lifetime,
		c.rx_packets,
		c.rx_bytes,
		c.tx_packets,
		c.tx_bytes,
		c.flags,
		byteorder.NetworkToHost(c.revnat),
		c.src_sec_id)
}

// CtEntryDump represents the key and value contained in the conntrack map.
type CtEntryDump struct {
	Key   CtKey
	Value CtEntry
}

const (
	// GCFilterNone doesn't filter the CT entries
	GCFilterNone = iota
	// GCFilterByTime filters CT entries by time
	GCFilterByTime
)

// GCFilterType is the type of a filter.
type GCFilterType uint

// GCFilter contains the necessary fields to filter the CT maps.
// Filtering by endpoint requires both EndpointID to be > 0 and
// EndpointIP to be not nil.
type GCFilter struct {
	Type       GCFilterType
	Time       uint32
	EndpointID uint16
	EndpointIP net.IP
}

// NewGCFilterBy creates a new GCFilter of the given type.
func NewGCFilterBy(filterType GCFilterType) *GCFilter {
	return &GCFilter{
		Type: filterType,
	}
}

// TypeString returns the filter type in human readable way.
func (f *GCFilter) TypeString() string {
	switch f.Type {
	case GCFilterNone:
		return "none"
	case GCFilterByTime:
		return "timeout"
	default:
		return "(unknown)"
	}
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
				value.lifetime,
				value.rx_packets,
				value.rx_bytes,
				value.tx_packets,
				value.tx_bytes,
				value.flags,
				byteorder.NetworkToHost(value.revnat),
				value.src_sec_id,
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
func doGC6(m *bpf.Map, filter *GCFilter) int {
	var (
		action, deleted, interrupted int
		prevKey, currentKey, nextKey CtKey6Global
	)

	// prevKey is initially invalid, causing GetNextKey to return the first key in the map as currentKey.
	prevKeyValid := false
	err := m.GetNextKey(&prevKey, &currentKey)
	if err != nil {
		// Map is empty, nothing to clean up.
		return 0
	}

	var count uint32
	for count = 1; count <= m.MapInfo.MaxEntries; count++ {
		// currentKey was returned by GetNextKey() so we know it existed in the map, but it may have been
		// deleted by a concurrent map operation. If currentKey is no longer in the map, nextKey will be
		// the first key in the map again. Use the nextKey only if we still find currentKey in the Lookup()
		// after the GetNextKey() call, this way we know nextKey is NOT the first key in the map.
		nextKeyValid := m.GetNextKey(&currentKey, &nextKey)
		entryMap, err := m.Lookup(&currentKey)
		if err != nil {
			// Restarting from a invalid key starts the iteration again from the beginning.
			// If we have a previously found key, try to restart from there instead
			if prevKeyValid {
				currentKey = prevKey
				// Restart from a given previous key only once, otherwise if the prevKey is
				// concurrently deleted we might loop forever trying to look it up.
				prevKeyValid = false
			} else {
				// Depending on exactly when currentKey was deleted from the map, nextKey may be the actual
				// keyelement after the deleted one, or the first element in the map.
				currentKey = nextKey
				interrupted++
			}
			continue
		}

		entry := entryMap.(*CtEntry)

		// In CT entries, the source address of the conntrack entry (`saddr`) is
		// the destination of the packet received, therefore it's the packet's
		// destination IP
		action = filter.doFiltering(currentKey.daddr.IP(), currentKey.saddr.IP(), currentKey.sport,
			uint8(currentKey.nexthdr), currentKey.flags, entry)

		switch action {
		case deleteEntry:
			err := m.Delete(&currentKey)
			if err != nil {
				log.WithError(err).Errorf("Unable to delete CT entry %s", currentKey.String())
			} else {
				deleted++
			}
		}

		if nextKeyValid != nil {
			break
		}
		// remember the last found key
		prevKey = currentKey
		prevKeyValid = true
		// continue from the next key
		currentKey = nextKey
	}

	metrics.DatapathErrors.With(labelIPv6CTDumpInterrupts).Add(float64(interrupted))
	if count > m.MapInfo.MaxEntries {
		log.WithError(err).WithField("interrupted", interrupted).Warning(
			"Garbage collection on IPv6 CT map failed to finish")
	}

	return deleted
}

// doGC4 iterates through a CTv4 map and drops entries based on the given
// filter.
func doGC4(m *bpf.Map, filter *GCFilter) int {
	var (
		action, deleted, interrupted int
		prevKey, currentKey, nextKey CtKey4Global
	)

	// prevKey is initially invalid, causing GetNextKey to return the first key in the map as currentKey.
	prevKeyValid := false
	err := m.GetNextKey(&prevKey, &currentKey)
	if err != nil {
		// Map is empty, nothing to clean up.
		return 0
	}

	var count uint32
	for count = 1; count <= m.MapInfo.MaxEntries; count++ {
		// currentKey was returned by GetNextKey() so we know it existed in the map, but it may have been
		// deleted by a concurrent map operation. If currentKey is no longer in the map, nextKey will be
		// the first key in the map again. Use the nextKey only if we still find currentKey in the Lookup()
		// after the GetNextKey() call, this way we know nextKey is NOT the first key in the map.
		nextKeyValid := m.GetNextKey(&currentKey, &nextKey)
		entryMap, err := m.Lookup(&currentKey)
		if err != nil {
			// Restarting from a invalid key starts the iteration again from the beginning.
			// If we have a previously found key, try to restart from there instead
			if prevKeyValid {
				currentKey = prevKey
				// Restart from a given previous key only once, otherwise if the prevKey is
				// concurrently deleted we might loop forever trying to look it up.
				prevKeyValid = false
			} else {
				// Depending on exactly when currentKey was deleted from the map, nextKey may be the actual
				// keyelement after the deleted one, or the first element in the map.
				currentKey = nextKey
				interrupted++
			}
			continue
		}

		entry := entryMap.(*CtEntry)

		// In CT entries, the source address of the conntrack entry (`saddr`) is
		// the destination of the packet received, therefore it's the packet's
		// destination IP
		action = filter.doFiltering(currentKey.daddr.IP(), currentKey.saddr.IP(), currentKey.sport,
			uint8(currentKey.nexthdr), currentKey.flags, entry)

		switch action {
		case deleteEntry:
			err := m.Delete(&currentKey)
			if err != nil {
				log.WithError(err).Errorf("Unable to delete CT entry %s", currentKey.String())
			} else {
				deleted++
			}
		}

		if nextKeyValid != nil {
			break
		}
		// remember the last found key
		prevKey = currentKey
		prevKeyValid = true
		// continue from the next key
		currentKey = nextKey
	}

	metrics.DatapathErrors.With(labelIPv4CTDumpInterrupts).Add(float64(interrupted))
	if count > m.MapInfo.MaxEntries {
		log.WithError(err).WithField("interrupted", interrupted).Warning(
			"Garbage collection on IPv4 CT map failed to finish")
	}

	return deleted
}

func (f *GCFilter) doFiltering(srcIP net.IP, dstIP net.IP, dstPort uint16, nextHdr, flags uint8, entry *CtEntry) (action int) {
	// Delete all entries with a lifetime smaller than f timestamp.
	if f.Type == GCFilterByTime && entry.lifetime < f.Time {
		return deleteEntry
	}

	return noAction
}

// GC runs garbage collection for map m with name mapName with the given filter.
// It returns how many items were deleted from m.
func GC(m *bpf.Map, mapName string, filter *GCFilter) int {
	if filter.Type == GCFilterByTime {
		// If LRUHashtable, no need to garbage collect as LRUHashtable cleans itself up.
		// FIXME: GH-3239 LRU logic is not handling timeouts gracefully enough
		// if m.MapInfo.MapType == bpf.MapTypeLRUHash {
		// 	return 0
		// }
		t, _ := bpf.GetMtime()
		tsec := t / 1000000000
		filter.Time = uint32(tsec)
	}

	switch mapName {
	case MapName6, MapName6Global:
		return doGC6(m, filter)
	case MapName4, MapName4Global:
		return doGC4(m, filter)
	default:
		return 0
	}
}

// Flush runs garbage collection for map m with the name mapName, deleting all
// entries. The specified map must be already opened using bpf.OpenMap().
func Flush(m *bpf.Map, mapName string) int {
	filter := NewGCFilterBy(GCFilterByTime)
	filter.Time = MaxTime

	switch mapName {
	case MapName6, MapName6Global:
		return doGC6(m, filter)
	case MapName4, MapName4Global:
		return doGC4(m, filter)
	default:
		return 0
	}
}
