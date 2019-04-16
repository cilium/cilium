// Copyright 2019 Authors of Cilium
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

	// CollisionRetriesDefault defines maximum retries for resolving port collisions.
	CollisionRetriesDefault = 16

	// DeterministicRetriesDefault defines maximum deterministic retries for
	// resolving port collisions.
	DeterministicRetriesDefault = 6

	// MaxEntries defines maximum NAT entries.
	MaxEntries = 524288

	mapCount = 2
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
	Dump(key tuple.TupleKey, start uint64) string
}

// NatDumpCreated returns time in seconds when NAT entry was created.
func NatDumpCreated(dumpStart, entryCreated uint64) string {
	tsecCreated := entryCreated / 1000000000
	tsecStart := dumpStart / 1000000000

	return fmt.Sprintf("%dsec", tsecStart-tsecCreated)
}

func nat4DumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	k, v := tuple.TupleKey4Global{}, NatEntry4{}

	if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
		return nil, nil, err
	}
	return &k, &v, nil
}

func nat6DumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	k, v := tuple.TupleKey6Global{}, NatEntry6{}

	if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
		return nil, nil, err
	}
	return &k, &v, nil
}

// NewMap instantiates a Map.
func NewMap(name string, v4 bool) *Map {
	var parser bpf.DumpParser
	var sizeKey, sizeVal int

	if v4 {
		sizeKey = int(unsafe.Sizeof(tuple.TupleKey4{}))
		sizeVal = int(unsafe.Sizeof(NatEntry4{}))
		parser = nat4DumpParser
	} else {
		sizeKey = int(unsafe.Sizeof(tuple.TupleKey6{}))
		sizeVal = int(unsafe.Sizeof(NatEntry6{}))
		parser = nat6DumpParser
	}
	return &Map{
		Map: *bpf.NewMap(
			name,
			bpf.MapTypeLRUHash,
			sizeKey,
			sizeVal,
			MaxEntries,
			0, 0,
			parser,
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
		key := k.(tuple.TupleKey)
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
	filterCallback := func(key bpf.MapKey, value bpf.MapValue) {
		currentKey := key.(*tuple.TupleKey4Global)
		err := m.Delete(currentKey)
		if err != nil {
			log.WithError(err).Errorf("Unable to delete CT entry %s", currentKey.String())
		} else {
			stats.deleted++
		}
	}
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)
	return stats
}

func doFlush6(m *Map) gcStats {
	stats := statStartGc(m)
	filterCallback := func(key bpf.MapKey, value bpf.MapValue) {
		currentKey := key.(*tuple.TupleKey6Global)
		err := m.Delete(currentKey)
		if err != nil {
			log.WithError(err).Errorf("Unable to delete CT entry %s", currentKey.String())
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
	key := *ctKey
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
	key := *ctKey
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

// DeleteMapping removes a NAT mapping from the global NAT table.
func (m *Map) DeleteMapping(key tuple.TupleKey) error {
	if key.GetFlags()&tuple.TUPLE_F_IN != 0 {
		return nil
	}
	if m.v4 {
		return deleteMapping4(m, key.(*tuple.TupleKey4Global))
	}
	return deleteMapping6(m, key.(*tuple.TupleKey6Global))
}

func maps(ipv4, ipv6 bool) []*Map {
	result := make([]*Map, 0, mapCount)
	if ipv4 {
		result = append(result, NewMap(MapNameSnat4Global, true))
	}
	if ipv6 {
		result = append(result, NewMap(MapNameSnat6Global, false))
	}
	return result
}

// GlobalMaps returns all global NAT maps.
func GlobalMaps(ipv4, ipv6 bool) []*Map {
	return maps(ipv4, ipv6)
}
