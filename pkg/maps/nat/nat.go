// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/timestamp"
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
	family IPFamily
}

// NatEntry is the interface describing values to the NAT map.
type NatEntry interface {
	bpf.MapValue

	// ToHost converts fields to host byte order.
	ToHost() NatEntry

	// Dumps the Nat entry as string.
	Dump(key NatKey, toDeltaSecs func(uint64) string) string
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

// NewMap instantiates a Map.
func NewMap(name string, family IPFamily, entries int) *Map {
	var mapKey bpf.MapKey
	var mapValue bpf.MapValue

	if family == IPv4 {
		mapKey = &NatKey4{}
		mapValue = &NatEntry4{}
	} else {
		mapKey = &NatKey6{}
		mapValue = &NatEntry6{}
	}

	return &Map{
		Map: *bpf.NewMap(
			name,
			ebpf.LRUHash,
			mapKey,
			mapValue,
			entries,
			0,
		).WithCache().
			WithEvents(option.Config.GetEventBufferConfig(name)).
			WithPressureMetric(),
		family: family,
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

// DumpEntriesWithTimeDiff iterates through Map m and writes the values of the
// nat entries in m to a string. If clockSource is not nil, it uses it to
// compute the time difference of each entry from now and prints that too.
func DumpEntriesWithTimeDiff(m NatMap, clockSource *models.ClockSource) (string, error) {
	var toDeltaSecs func(uint64) string
	var sb strings.Builder

	if clockSource == nil {
		toDeltaSecs = func(t uint64) string {
			return fmt.Sprintf("? (raw %d)", t)
		}
	} else {
		now, err := timestamp.GetCTCurTime(clockSource)
		if err != nil {
			return "", err
		}
		tsConverter, err := timestamp.NewCTTimeToSecConverter(clockSource)
		if err != nil {
			return "", err
		}
		tsecNow := tsConverter(now)
		toDeltaSecs = func(t uint64) string {
			tsec := tsConverter(uint64(t))
			diff := int64(tsecNow) - int64(tsec)
			return fmt.Sprintf("%dsec ago", diff)
		}
	}

	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(NatKey)
		if !key.ToHost().Dump(&sb, false) {
			return
		}
		val := v.(NatEntry)
		sb.WriteString(val.ToHost().Dump(key, toDeltaSecs))
	}
	err := m.DumpWithCallback(cb)
	return sb.String(), err
}

// DoDumpEntries iterates through Map m and writes the values of the
// nat entries in m to a string.
func DoDumpEntries(m NatMap) (string, error) {
	return DumpEntriesWithTimeDiff(m, nil)
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
			log.WithError(err).WithField(logfields.Key, key.String()).Error("Unable to delete NAT entry")
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
			log.WithError(err).WithField(logfields.Key, key.String()).Error("Unable to delete NAT entry")
		} else {
			stats.deleted++
		}
	}
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)
	return stats
}

// Flush deletes all NAT mappings from the given table.
func (m *Map) Flush() int {
	if m.family == IPv4 {
		return int(doFlush4(m).deleted)
	}

	return int(doFlush6(m).deleted)
}

func DeleteMapping4(m *Map, ctKey *tuple.TupleKey4Global) error {
	key := NatKey4{
		TupleKey4Global: *ctKey,
	}
	// Workaround #5848.
	addr := key.SourceAddr
	key.SourceAddr = key.DestAddr
	key.DestAddr = addr
	valMap, err := m.Lookup(&key)
	if err == nil {
		val := *(valMap.(*NatEntry4))
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

func DeleteMapping6(m *Map, ctKey *tuple.TupleKey6Global) error {
	key := NatKey6{
		TupleKey6Global: *ctKey,
	}
	// Workaround #5848.
	addr := key.SourceAddr
	key.SourceAddr = key.DestAddr
	key.DestAddr = addr
	valMap, err := m.Lookup(&key)
	if err == nil {
		val := *(valMap.(*NatEntry6))
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
func DeleteSwappedMapping4(m *Map, ctKey *tuple.TupleKey4Global) error {
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
func DeleteSwappedMapping6(m *Map, ctKey *tuple.TupleKey6Global) error {
	key := NatKey6{TupleKey6Global: *ctKey}
	// Because of #5848, we need to reverse only ports
	port := key.SourcePort
	key.SourcePort = key.DestPort
	key.DestPort = port
	key.Flags = tuple.TUPLE_F_OUT
	m.SilentDelete(&key)

	return nil
}

// GlobalMaps returns all global NAT maps.
func GlobalMaps(ipv4, ipv6, nodeport bool) (ipv4Map, ipv6Map *Map) {
	if !nodeport {
		return
	}
	if ipv4 {
		ipv4Map = NewMap(MapNameSnat4Global, IPv4, maxEntries())
	}
	if ipv6 {
		ipv6Map = NewMap(MapNameSnat6Global, IPv6, maxEntries())
	}
	return
}

// ClusterMaps returns all NAT maps for given clusters
func ClusterMaps(clusterID uint32, ipv4, ipv6 bool) (ipv4Map, ipv6Map *Map, err error) {
	if ipv4 {
		ipv4Map, err = GetClusterNATMap(clusterID, IPv4)
		if err != nil {
			return
		}
	}
	if ipv6 {
		ipv6Map, err = GetClusterNATMap(clusterID, IPv6)
		if err != nil {
			return
		}
	}
	return
}

func maxEntries() int {
	if option.Config.NATMapEntriesGlobal != 0 {
		return option.Config.NATMapEntriesGlobal
	}
	return option.LimitTableMax
}
