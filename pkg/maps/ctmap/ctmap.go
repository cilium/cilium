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
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"

	log "github.com/Sirupsen/logrus"
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
)

type CtType int

// CtKey is the interface describing keys to the conntrack maps.
type CtKey interface {
	bpf.MapKey

	// Returns human readable string representation
	String() string

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
	revnat     uint16
	proxy_port uint16
	src_sec_id uint32
}

// GetValuePtr returns the unsafe.Pointer for s.
func (c *CtEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(c) }

// CtEntryDump represents the key and value contained in the conntrack map.
type CtEntryDump struct {
	Key   CtKey
	Value CtEntry
}

const (
	// GCFilterByTime filters CT entries by time
	GCFilterByTime = 1 << iota
	// GCFilterByID filters CT entries by IP and IDsToRem
	GCFilterByID
)

// GCFilterFlags is the type for the different filter flags
type GCFilterFlags uint

// GCFilter contains the necessary fields to filter the CT maps.
type GCFilter struct {
	Time    uint32
	IP      net.IP
	IDsToRm map[uint32]bool
	fType   GCFilterFlags
}

// NewGCFilterBy creates a new GCFilter with the given flags.
func NewGCFilterBy(f GCFilterFlags) *GCFilter {
	return &GCFilter{
		fType:   f,
		IDsToRm: map[uint32]bool{},
	}
}

// TypeString returns the filter type in human readable way.
func (f *GCFilter) TypeString() string {
	switch f.fType {
	case GCFilterByTime:
		return "timeout"
	case GCFilterByID:
		return "security ID"
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
			fmt.Sprintf(" expires=%d rx_packets=%d rx_bytes=%d tx_packets=%d tx_bytes=%d flags=%x revnat=%d proxyport=%d src_sec_id=%d\n",
				value.lifetime,
				value.rx_packets,
				value.rx_bytes,
				value.tx_packets,
				value.tx_bytes,
				value.flags,
				byteorder.NetworkToHost(value.revnat),
				byteorder.NetworkToHost(value.proxy_port),
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
		deleted         int
		nextKey, tmpKey CtKey6Global
		del             bool
	)

	err := m.GetNextKey(&tmpKey, &nextKey)
	if err != nil {
		return 0
	}

	for {
		del = false
		nextKeyValid := m.GetNextKey(&nextKey, &tmpKey)
		entryMap, err := m.Lookup(&nextKey)
		if err != nil {
			log.Errorf("error during map Lookup: %s", err)
			break
		}

		entry := entryMap.(*CtEntry)

		// FIXME create a single function for doGC4 and doGC6

		if filter.fType&GCFilterByTime != 0 &&
			entry.lifetime < filter.Time {

			del = true
			//log.Debugf("Deleting entry %v since it timeout", entry)
		}
		if filter.fType&GCFilterByID != 0 &&
			// In CT's entries, saddr is the packet's receiver,
			// which means, is the destination container IP.
			nextKey.saddr.IP().Equal(filter.IP) {

			// Check if the src_sec_id of that entry is not allowed
			// to talk with the destination container IP.
			if _, ok := filter.IDsToRm[entry.src_sec_id]; ok {

				del = true
				//log.Debugf("Deleting entry since ID %d is no "+
				//	"longer being consumed by %s", entry.src_sec_id, filter.IP)
			}
		}

		if del {
			err := m.Delete(&nextKey)
			if err != nil {
				log.Debugf("error during Delete: %s", err)
			} else {
				deleted++
			}
		}

		if nextKeyValid != nil {
			break
		}
		nextKey = tmpKey
	}
	return deleted
}

// doGC4 iterates through a CTv4 map and drops entries based on the given
// filter.
func doGC4(m *bpf.Map, filter *GCFilter) int {
	var (
		deleted         int
		nextKey, tmpKey CtKey4Global
		del             bool
	)

	err := m.GetNextKey(&tmpKey, &nextKey)
	if err != nil {
		return 0
	}

	for true {
		del = false
		nextKeyValid := m.GetNextKey(&nextKey, &tmpKey)
		entryMap, err := m.Lookup(&nextKey)
		if err != nil {
			log.Errorf("error during map Lookup: %s", err)
			break
		}

		entry := entryMap.(*CtEntry)

		// FIXME create a single function for doGC4 and doGC6

		if filter.fType&GCFilterByTime != 0 &&
			entry.lifetime < filter.Time {

			del = true
			//log.Debugf("Deleting entry %v since it timeout", entry)
		}
		if filter.fType&GCFilterByID != 0 &&
			// In CT's entries, saddr is the packet's receiver,
			// which means, is the destination container IP.
			nextKey.saddr.IP().Equal(filter.IP) {

			// Check if the src_sec_id of that entry is not allowed
			// to talk with the destination container IP.
			if _, ok := filter.IDsToRm[entry.src_sec_id]; ok {

				del = true
				//log.Debugf("Deleting entry since ID %d is no "+
				//	"longer being consumed by %s", entry.src_sec_id, filter.IP)
			}
		}

		if del {
			err := m.Delete(&nextKey)
			if err != nil {
				log.Debugf("error during Delete: %s", err)
			} else {
				deleted++
			}
		}

		if nextKeyValid != nil {
			break
		}
		nextKey = tmpKey
	}
	return deleted
}

// GC runs garbage collection for map m with name mapName with the given filter.
// It returns how many items were deleted from m.
func GC(m *bpf.Map, mapName string, filter *GCFilter) int {
	if filter.fType&GCFilterByTime != 0 {
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
