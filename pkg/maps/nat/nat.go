// Copyright 2019-2020 Authors of Cilium
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

package nat

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-nat")
)

const (
	// MapNameSnat4Global represents global IPv4 NAT table.
	MapNameSnat4Global = "cilium_snat_v4_external"
	// MapNameSnat6Global represents global IPv6 NAT table.
	MapNameSnat6Global = "cilium_snat_v6_external"

	// MinPortSnatDefault represents default min port from range.
	MinPortSnatDefault = 1024
	// MaxPortSnatDefault represents default max port from range.
	MaxPortSnatDefault = 65535
)

// Map represents a NAT map.
type Map struct {
	bpf.Map
	v4 bool
}

// NatEntry is the interface describing values to the NAT map.
type NatEntry interface {
	bpf.MapValue

	// ToHost converts fields to host byte order.
	ToHost() NatEntry

	// Dumps the Nat entry as string.
	Dump(key NatKey, start uint64) string
}

// NatDumpCreated returns time in seconds when NAT entry was created.
func NatDumpCreated(dumpStart, entryCreated uint64) string {
	tsecCreated := entryCreated / 1000000000
	tsecStart := dumpStart / 1000000000

	return fmt.Sprintf("%dsec", tsecStart-tsecCreated)
}

// NewMap instantiates a Map.
func NewMap(name string, v4, lru bool, entries int) *Map {
	var sizeKey, sizeVal int
	var mapKey bpf.MapKey
	var mapValue bpf.MapValue
	var mapType bpf.MapType

	if v4 {
		mapKey = &NatKey4{}
		sizeKey = int(unsafe.Sizeof(NatKey4{}))
		mapValue = &NatEntry4{}
		sizeVal = int(unsafe.Sizeof(NatEntry4{}))
	} else {
		mapKey = &NatKey6{}
		sizeKey = int(unsafe.Sizeof(NatKey6{}))
		mapValue = &NatEntry6{}
		sizeVal = int(unsafe.Sizeof(NatEntry6{}))
	}
	if lru {
		mapType = bpf.MapTypeLRUHash
	} else {
		mapType = bpf.MapTypeHash
	}
	return &Map{
		Map: *bpf.NewMap(
			name,
			mapType,
			mapKey,
			sizeKey,
			mapValue,
			sizeVal,
			entries,
			0, 0,
			bpf.ConvertKeyValue,
		).WithCache(),
		v4: v4,
	}
}

// DumpEntries iterates through Map m and writes the values of the
// nat entries in m to a string.
func (m *Map) DumpEntries() (string, error) {
	var buffer bytes.Buffer

	nsecStart, _ := bpf.GetMtime()
	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(NatKey)
		if !key.ToHost().Dump(&buffer, false) {
			return
		}
		val := v.(NatEntry)
		buffer.WriteString(val.ToHost().Dump(key, nsecStart))
	}
	err := m.DumpWithCallback(cb)
	return buffer.String(), err
}

type gcStats struct {
	*bpf.DumpStats

	// deleted is the number of keys deleted
	deleted uint32

	// dumpError records any error that occurred during the dump.
	dumpError error
}

func statStartGc(m *Map) gcStats {
	return gcStats{
		DumpStats: bpf.NewDumpStats(&m.Map),
	}
}

func doFlush4(m *Map) gcStats {
	stats := statStartGc(m)
	filterCallback := func(key bpf.MapKey, _ bpf.MapValue) {
		err := m.Delete(key)
		if err != nil {
			log.WithError(err).WithField(logfields.Key, key.String()).Error("Unable to delete CT entry")
		} else {
			stats.deleted++
		}
	}
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)
	return stats
}

func doFlush6(m *Map) gcStats {
	stats := statStartGc(m)
	filterCallback := func(key bpf.MapKey, _ bpf.MapValue) {
		err := m.Delete(key)
		if err != nil {
			log.WithError(err).WithField(logfields.Key, key.String()).Error("Unable to delete CT entry")
		} else {
			stats.deleted++
		}
	}
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)
	return stats
}

// Flush deletes all NAT mappings from the given table.
func (m *Map) Flush() int {
	if m.v4 {
		return int(doFlush4(m).deleted)
	}
	return int(doFlush6(m).deleted)
}

func deleteMapping4(m *Map, ctKey *tuple.TupleKey4Global) error {
	key := NatKey4{
		TupleKey4Global: *ctKey,
	}
	// Workaround #5848.
	addr := key.SourceAddr
	key.SourceAddr = key.DestAddr
	key.DestAddr = addr
	valMap, err := m.Lookup(&key)
	if err == nil {
		val := *(*NatEntry4)(unsafe.Pointer(valMap.GetValuePtr()))
		rkey := key
		rkey.SourceAddr = key.DestAddr
		rkey.SourcePort = key.DestPort
		rkey.DestAddr = val.Addr
		rkey.DestPort = val.Port
		rkey.Flags = tuple.TUPLE_F_IN

		m.Delete(&key)
		m.Delete(&rkey)
	}
	return nil
}

func deleteMapping6(m *Map, ctKey *tuple.TupleKey6Global) error {
	key := NatKey6{
		TupleKey6Global: *ctKey,
	}
	// Workaround #5848.
	addr := key.SourceAddr
	key.SourceAddr = key.DestAddr
	key.DestAddr = addr
	valMap, err := m.Lookup(&key)
	if err == nil {
		val := *(*NatEntry6)(unsafe.Pointer(valMap.GetValuePtr()))
		rkey := key
		rkey.SourceAddr = key.DestAddr
		rkey.SourcePort = key.DestPort
		rkey.DestAddr = val.Addr
		rkey.DestPort = val.Port
		rkey.Flags = tuple.TUPLE_F_IN

		m.Delete(&key)
		m.Delete(&rkey)
	}
	return nil
}

// Expects ingress tuple
func deleteSwappedMapping4(m *Map, ctKey *tuple.TupleKey4Global) error {
	key := NatKey4{TupleKey4Global: *ctKey}
	// Because of #5848, we need to reverse only ports
	port := key.SourcePort
	key.SourcePort = key.DestPort
	key.DestPort = port
	key.Flags = tuple.TUPLE_F_OUT
	m.Delete(&key)

	return nil
}

// Expects ingress tuple
func deleteSwappedMapping6(m *Map, ctKey *tuple.TupleKey6Global) error {
	key := NatKey6{TupleKey6Global: *ctKey}
	// Because of #5848, we need to reverse only ports
	port := key.SourcePort
	key.SourcePort = key.DestPort
	key.DestPort = port
	key.Flags = tuple.TUPLE_F_OUT
	m.Delete(&key)

	return nil
}

// DeleteMapping removes a NAT mapping from the global NAT table.
func (m *Map) DeleteMapping(key tuple.TupleKey) error {
	if key.GetFlags()&tuple.TUPLE_F_IN != 0 {
		if m.v4 {
			// To delete NAT entries created by DSR
			return deleteSwappedMapping4(m, key.(*tuple.TupleKey4Global))
		}
		return deleteSwappedMapping6(m, key.(*tuple.TupleKey6Global))
	}

	if m.v4 {
		return deleteMapping4(m, key.(*tuple.TupleKey4Global))
	}
	return deleteMapping6(m, key.(*tuple.TupleKey6Global))
}

// GlobalMaps returns all global NAT maps.
func GlobalMaps(ipv4, ipv6, lru bool) (ipv4Map, ipv6Map *Map) {
	entries := option.Config.NATMapEntriesGlobal
	if entries == 0 {
		entries = option.LimitTableMax
	}
	if ipv4 {
		ipv4Map = NewMap(MapNameSnat4Global, true, lru, entries)
	}
	if ipv6 {
		ipv6Map = NewMap(MapNameSnat6Global, false, lru, entries)
	}
	return
}
