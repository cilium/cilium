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
	"unsafe"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"

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

	// Convert converts fields between host byte order and map byte order
	// if necessary.
	Convert() CtKey

	// Dumps contents of key to buffer. Returns true if successful.
	Dump(buffer *bytes.Buffer) bool
}

// CtValue is the interface describing values in the conntrack maps.
type CtValue interface {
	bpf.MapValue

	// Convert converts fields between host byte order and map byte order
	// if necessary.
	Convert() CtValue
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
}

// GetValuePtr returns the unsafe.Pointer for s.
func (c *CtEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(c) }

// CtEntryDump represents the key and value contained in the conntrack map.
type CtEntryDump struct {
	Key   CtKey
	Value CtEntry
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
		if !entry.Key.Dump(&buffer) {
			continue
		}

		value := entry.Value
		buffer.WriteString(
			fmt.Sprintf(" expires=%d rx_packets=%d rx_bytes=%d tx_packets=%d tx_bytes=%d flags=%x revnat=%d proxyport=%d\n",
				value.lifetime,
				value.rx_packets,
				value.rx_bytes,
				value.tx_packets,
				value.tx_bytes,
				value.flags,
				common.Swab16(value.revnat),
				common.Swab16(value.proxy_port)),
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

// doGC6 iterates through a CTv6 map and drops entries when they timeout.
func doGC6(m *bpf.Map, deleted *int, time uint32) {
	var nextKey, tmpKey CtKey6Global

	err := m.GetNextKey(&tmpKey, &nextKey)
	if err != nil {
		return
	}

	for true {
		nextKeyValid := m.GetNextKey(&nextKey, &tmpKey)
		entryMap, err := m.Lookup(&nextKey)
		if err != nil {
			log.Errorf("error during map Lookup: %s", err)
			break
		}

		entry := entryMap.(*CtEntry)
		if entry.lifetime < time {
			err := m.Delete(&nextKey)
			if err != nil {
				log.Debugf("error during Delete: %s", err)
			} else {
				(*deleted)++
			}
		}

		if nextKeyValid != nil {
			break
		}
		nextKey = tmpKey
	}
}

// doGC4 iterates through a CTv4 map and drops entries when they timeout.
func doGC4(m *bpf.Map, deleted *int, time uint32) {
	var nextKey, tmpKey CtKey4Global

	err := m.GetNextKey(&tmpKey, &nextKey)
	if err != nil {
		return
	}

	for true {
		nextKeyValid := m.GetNextKey(&nextKey, &tmpKey)
		entryMap, err := m.Lookup(&nextKey)
		if err != nil {
			log.Errorf("error during map Lookup: %s", err)
			break
		}

		entry := entryMap.(*CtEntry)
		if entry.lifetime < time {
			err := m.Delete(&nextKey)
			if err != nil {
				log.Debugf("error during Delete: %s", err)
			} else {
				(*deleted)++
			}
		}

		if nextKeyValid != nil {
			break
		}
		nextKey = tmpKey
	}
}

// GC runs garbage collection for map m with name mapName with interval interval.
// It returns how many items were deleted from m.
func GC(m *bpf.Map, mapName string) int {
	t, _ := bpf.GetMtime()
	tsec := t / 1000000000
	deleted := 0

	switch mapName {
	case MapName6, MapName6Global:
		doGC6(m, &deleted, uint32(tsec))
	case MapName4, MapName4Global:
		doGC4(m, &deleted, uint32(tsec))
	}

	return deleted
}
