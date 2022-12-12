// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"fmt"
	"strings"
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
// It also implements the NatMap interface.
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

// A "Record" designates a map entry (key + value), but avoid "entry" because of
// possible confusion with "NatEntry" (actually the value part).
// This type is used for JSON dump and mock maps.
type NatMapRecord struct {
	Key   NatKey
	Value NatEntry
}

// NatMap interface represents a NAT map, and can be reused to implement mock
// maps for unit tests.
type NatMap interface {
	Open() error
	Close() error
	Path() (string, error)
	DumpEntries() (string, error)
	DumpWithCallback(bpf.DumpCallback) error
}

// NatDumpCreated returns time in seconds when NAT entry was created.
func NatDumpCreated(dumpStart, entryCreated uint64) string {
	tsecCreated := entryCreated / 1000000000
	tsecStart := dumpStart / 1000000000

	return fmt.Sprintf("%dsec", tsecStart-tsecCreated)
}

// NewMap instantiates a Map.
func NewMap(name string, v4 bool, entries int) *Map {
	var sizeKey, sizeVal int
	var mapKey bpf.MapKey
	var mapValue bpf.MapValue

	if v4 {
		mapKey = &NatKey4{}
		sizeKey = SizeofNatKey4
		mapValue = &NatEntry4{}
		sizeVal = SizeofNatEntry4
	} else {
		mapKey = &NatKey6{}
		sizeKey = SizeofNatKey6
		mapValue = &NatEntry6{}
		sizeVal = SizeofNatEntry6
	}

	return &Map{
		Map: *bpf.NewMap(
			name,
			bpf.MapTypeLRUHash,
			mapKey,
			sizeKey,
			mapValue,
			sizeVal,
			entries,
			0,
			bpf.ConvertKeyValue,
		).WithCache().WithEvents(option.Config.GetEventBufferConfig(name)),
		v4: v4,
	}
}

func (m *Map) Delete(k bpf.MapKey) (deleted bool, err error) {
	deleted, err = (&m.Map).SilentDelete(k)
	return
}

func (m *Map) DumpStats() *bpf.DumpStats {
	return bpf.NewDumpStats(&m.Map)
}

func (m *Map) DumpReliablyWithCallback(cb bpf.DumpCallback, stats *bpf.DumpStats) error {
	return (&m.Map).DumpReliablyWithCallback(cb, stats)
}

// DoDumpEntries iterates through Map m and writes the values of the
// nat entries in m to a string.
func DoDumpEntries(m NatMap) (string, error) {
	var sb strings.Builder

	nsecStart, _ := bpf.GetMtime()
	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(NatKey)
		if !key.ToHost().Dump(&sb, false) {
			return
		}
		val := v.(NatEntry)
		sb.WriteString(val.ToHost().Dump(key, nsecStart))
	}
	err := m.DumpWithCallback(cb)
	return sb.String(), err
}

// DumpEntries iterates through Map m and writes the values of the
// nat entries in m to a string.
func (m *Map) DumpEntries() (string, error) {
	return DoDumpEntries(m)
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
		err := (&m.Map).Delete(key)
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
		err := (&m.Map).Delete(key)
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

		m.SilentDelete(&key)
		m.SilentDelete(&rkey)
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

		m.SilentDelete(&key)
		m.SilentDelete(&rkey)
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
	m.SilentDelete(&key)

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
	m.SilentDelete(&key)

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
func GlobalMaps(ipv4, ipv6, nodeport bool) (ipv4Map, ipv6Map *Map) {
	if !nodeport {
		return
	}
	entries := option.Config.NATMapEntriesGlobal
	if entries == 0 {
		entries = option.LimitTableMax
	}
	if ipv4 {
		ipv4Map = NewMap(MapNameSnat4Global, true, entries)
	}
	if ipv6 {
		ipv6Map = NewMap(MapNameSnat6Global, false, entries)
	}
	return
}

// ClusterMaps returns all NAT maps for given clusters
func ClusterMaps(clusterID uint32, ipv4, ipv6 bool) (ipv4Map, ipv6Map *Map, err error) {
	if PerClusterNATMaps == nil {
		err = fmt.Errorf("Per-cluster NAT maps are not initialized")
		return
	}
	if ipv4 {
		ipv4Map, err = PerClusterNATMaps.GetClusterNATMap(clusterID, true)
		if err != nil {
			return
		}
	}
	if ipv6 {
		ipv6Map, err = PerClusterNATMaps.GetClusterNATMap(clusterID, false)
		if err != nil {
			return
		}
	}
	return
}
