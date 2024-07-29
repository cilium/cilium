// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/timestamp"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
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

	mapInfo map[mapType]mapAttributes
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

	mapNumEntriesLocal = 64000

	TUPLE_F_OUT     = 0
	TUPLE_F_IN      = 1
	TUPLE_F_RELATED = 2
	TUPLE_F_SERVICE = 4

	// MaxTime specifies the last possible time for GCFilter.Time
	MaxTime = math.MaxUint32

	metricsAlive   = "alive"
	metricsDeleted = "deleted"

	metricsIngress = "ingress"
	metricsEgress  = "egress"
)

type action int

const (
	noAction action = iota
	deleteEntry
)

var globalDeleteLock [mapTypeMax]lock.Mutex

type mapAttributes struct {
	natMapLock *lock.Mutex // Serializes concurrent accesses to natMap
	natMap     *nat.Map
}

// CtMap interface represents a CT map, and can be reused to implement mock
// maps for unit tests.
type CtMap interface {
	Open() error
	Close() error
	Path() (string, error)
	DumpEntries() (string, error)
	DumpWithCallback(bpf.DumpCallback) error
	Count() (int, error)
	Update(key bpf.MapKey, value bpf.MapValue) error
}

// A "Record" designates a map entry (key + value), but avoid "entry" because of
// possible confusion with "CtEntry" (actually the value part).
// This type is used for JSON dump and mock maps.
type CtMapRecord struct {
	Key   CtKey
	Value CtEntry
}

// InitMapInfo builds the information about different CT maps for the
// combination of L3/L4 protocols.
func InitMapInfo(v4, v6, nodeport bool) {
	global4Map, global6Map := nat.GlobalMaps(v4, v6, nodeport)
	global4MapLock := &lock.Mutex{}
	global6MapLock := &lock.Mutex{}

	// SNAT also only works if the CT map is global so all local maps will be nil
	mapInfo = map[mapType]mapAttributes{
		mapTypeIPv4TCPGlobal: {natMap: global4Map, natMapLock: global4MapLock},
		mapTypeIPv6TCPGlobal: {natMap: global6Map, natMapLock: global6MapLock},
		mapTypeIPv4AnyGlobal: {natMap: global4Map, natMapLock: global4MapLock},
		mapTypeIPv6AnyGlobal: {natMap: global6Map, natMapLock: global6MapLock},
	}
}

// CtEndpoint represents an endpoint for the functions required to manage
// conntrack maps for the endpoint.
type CtEndpoint interface {
	GetID() uint64
}

// Map represents an instance of a BPF connection tracking map.
// It also implements the CtMap interface.
type Map struct {
	bpf.Map

	mapType mapType
	// define maps to the macro used in the datapath portion for the map
	// name, for example 'CT_MAP4'.
	define string

	// This field indicates which cluster this ctmap is. Zero for global
	// maps and non-zero for per-cluster maps.
	clusterID uint32
}

// GCFilter contains the necessary fields to filter the CT maps.
// Filtering by endpoint requires both EndpointID to be > 0 and
// EndpointIP to be not nil.
type GCFilter struct {
	// RemoveExpired enables removal of all entries that have expired
	RemoveExpired bool

	// Time is the reference timestamp to remove expired entries. If
	// RemoveExpired is true and lifetime is lesser than Time, the entry is
	// removed
	Time uint32

	// ValidIPs is the list of valid IPs to scrub all entries for which the
	// source or destination IP is *not* matching one of the valid IPs.
	ValidIPs map[netip.Addr]struct{}

	// MatchIPs is the list of IPs to remove from the conntrack table
	MatchIPs map[netip.Addr]struct{}

	// EmitCTEntry is called, when non-nil, if filtering by ValidIPs and MatchIPs
	// passes. It has no impact on CT GC, but can be used to iterate over valid
	// CT entries.
	EmitCTEntryCB EmitCTEntryCBFunc
}

// EmitCTEntryCBFunc is the type used for the EmitCTEntryCB callback in GCFilter
type EmitCTEntryCBFunc func(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, nextHdr, flags uint8, entry *CtEntry)

// TODO: GH-33557: Remove this hack once ctmap is migrated to a cell.
type PurgeHook interface {
	CountFailed4(uint16, uint32)
	CountFailed6(uint16, uint32)
}

var ACT PurgeHook

// DumpEntriesWithTimeDiff iterates through Map m and writes the values of the
// ct entries in m to a string. If clockSource is not nil, it uses it to
// compute the time difference of each entry from now and prints that too.
func DumpEntriesWithTimeDiff(m CtMap, clockSource *models.ClockSource) (string, error) {
	var toRemSecs func(uint32) string

	if clockSource == nil {
		toRemSecs = nil
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
		toRemSecs = func(t uint32) string {
			tsec := tsConverter(uint64(t))
			diff := int64(tsec) - int64(tsecNow)
			return fmt.Sprintf("remaining: %d sec(s)", diff)
		}
	}

	var sb strings.Builder
	cb := func(k bpf.MapKey, v bpf.MapValue) {
		// No need to deep copy as the values are used to create new strings
		key := k.(CtKey)
		if !key.ToHost().Dump(&sb, true) {
			return
		}
		value := v.(*CtEntry)
		sb.WriteString(value.StringWithTimeDiff(toRemSecs))
	}
	// DumpWithCallback() must be called before sb.String().
	err := m.DumpWithCallback(cb)
	if err != nil {
		return "", err
	}
	return sb.String(), err
}

// DoDumpEntries iterates through Map m and writes the values of the ct entries
// in m to a string.
func DoDumpEntries(m CtMap) (string, error) {
	return DumpEntriesWithTimeDiff(m, nil)
}

// DumpEntries iterates through Map m and writes the values of the ct entries
// in m to a string.
func (m *Map) DumpEntries() (string, error) {
	return DoDumpEntries(m)
}

// Count batch dumps the Map m and returns the count of the entries.
func (m *Map) Count() (count int, err error) {
	global := m.mapType.isGlobal()
	v4 := m.mapType.isIPv4()
	switch {
	case global && v4:
		return countBatch[CtKey4Global](m)
	case global && !v4:
		return countBatch[CtKey6Global](m)
	case !global && v4:
		return countBatch[CtKey4](m)
	case !global && !v4:
		return countBatch[CtKey6](m)
	}
	return
}

func countBatch[T any](m *Map) (count int, err error) {
	// If we have a hash map of N = 2^n elements, then the first collision is
	// expected [at random] when we insert around sqrt(2*N) elements. For
	// example, for a map of size 1024, this is around 45 elements. In normal
	// life input is not uniformly distributed, so there could be more
	// collisions.
	//
	// In practice, we can expect maximum collision lengths (# of elements in a
	// bucket ~= chunkSize) to be around 30-40. So anything like chunk_size=10%
	// of map size should be pretty safe. If the chunkSize is not enough, then
	// the kernel returns ENOSPC. In this case, it is possible to just set
	// chunkSize *= 2 and try again. However, with the current chunkSize of
	// 4096, we observe no issues dumping the maximum size of a CT map. As
	// explained a bit below, 4096 was an optimal number considering idle
	// memory usage and benchmarks (see commit msg).
	//
	// Credits to Anton for the above explanation of htab maps.
	const chunkSize uint32 = 4096

	// We can reuse the following buffers as the batch lookup does not care for
	// the contents of the map. This saves on redundant memory allocations.
	//
	// The following is the number of KiB total that is allocated by Go for the
	// following buffers based on the data type:
	//   >>> (14*4096) / 1024 # CT IPv4 map key
	//   56.0
	//   >>> (38*4096) / 1024 # CT IPv6 map key
	//   152.0
	//   >>> (56*4096) / 1024 # CT map value
	//   224.0
	kout := make([]T, chunkSize)
	vout := make([]CtEntry, chunkSize)

	var cursor ebpf.MapBatchCursor
	for {
		c, batchErr := m.BatchLookup(&cursor, kout, vout, nil)
		count += c
		if batchErr != nil {
			if errors.Is(batchErr, ebpf.ErrKeyNotExist) {
				return count, nil // end of map, we're done iterating
			}
			return count, batchErr
		}
	}
}

// OpenCTMap is a convenience function to open CT maps. It is the
// responsibility of the caller to ensure that m.Close() is called after this
// function.
func OpenCTMap(m CtMap) (path string, err error) {
	path, err = m.Path()
	if err == nil {
		err = m.Open()
	}
	return
}

// newMap creates a new CT map of the specified type with the specified name.
func newMap(mapName string, m mapType) *Map {
	result := &Map{
		Map: *bpf.NewMap(mapName,
			ebpf.LRUHash,
			m.key(),
			m.value(),
			m.maxEntries(),
			0,
		).WithPressureMetric(),
		mapType: m,
		define:  m.bpfDefine(),
	}
	return result
}

func purgeCtEntry6(m *Map, key CtKey, entry *CtEntry, natMap *nat.Map) error {
	err := m.Delete(key)
	if err != nil {
		return err
	}

	t := key.GetTupleKey()
	tupleType := t.GetFlags()

	if tupleType == tuple.TUPLE_F_SERVICE && ACT != nil {
		ACT.CountFailed6(entry.RevNAT, uint32(entry.BackendID))
	}

	if natMap == nil {
		return nil
	}

	if tupleType == tuple.TUPLE_F_OUT {
		if entry.isDsrInternalEntry() {
			// To delete NAT entries created by DSR
			nat.DeleteSwappedMapping6(natMap, t.(*tuple.TupleKey6Global))
		} else {
			// To delete NAT entries created for SNAT
			nat.DeleteMapping6(natMap, t.(*tuple.TupleKey6Global))

		}
	}

	return nil
}

// doGC6 iterates through a CTv6 map and drops entries based on the given
// filter.
func doGC6(m *Map, filter *GCFilter) gcStats {
	var natMap *nat.Map

	if m.clusterID == 0 {
		// global map handling
		ctMap := mapInfo[m.mapType]
		if ctMap.natMapLock != nil {
			ctMap.natMapLock.Lock()
			defer ctMap.natMapLock.Unlock()
		}
		natMap = ctMap.natMap
	} else {
		// per-cluster map handling
		natm, err := nat.GetClusterNATMap(m.clusterID, nat.IPv6)
		if err != nil {
			log.WithError(err).Error("Unable to get per-cluster NAT map")
		} else {
			natMap = natm
		}
	}

	stats := statStartGc(m)
	defer stats.finish()

	if natMap != nil {
		err := natMap.Open()
		if err == nil {
			defer natMap.Close()
		} else {
			natMap = nil
		}
	}

	filterCallback := func(key bpf.MapKey, value bpf.MapValue) {
		entry := value.(*CtEntry)

		switch obj := key.(type) {
		case *CtKey6Global:
			currentKey6Global := obj
			// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
			// the destination of the packet received, therefore it's the packet's
			// destination IP
			action := filter.doFiltering(currentKey6Global.DestAddr.Addr(), currentKey6Global.SourceAddr.Addr(),
				currentKey6Global.DestPort, currentKey6Global.SourcePort,
				uint8(currentKey6Global.NextHeader), currentKey6Global.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry6(m, currentKey6Global, entry, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey6Global.String()).Error("Unable to delete CT entry")
				} else {
					stats.deleted++
				}
			default:
				stats.aliveEntries++
			}
		case *CtKey6:
			currentKey6 := obj
			// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
			// the destination of the packet received, therefore it's the packet's
			// destination IP
			action := filter.doFiltering(currentKey6.DestAddr.Addr(), currentKey6.SourceAddr.Addr(),
				currentKey6.DestPort, currentKey6.SourcePort,
				uint8(currentKey6.NextHeader), currentKey6.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry6(m, currentKey6, entry, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey6.String()).Error("Unable to delete CT entry")
				} else {
					stats.deleted++
				}
			default:
				stats.aliveEntries++
			}
		default:
			log.Warningf("Encountered unknown type while scanning conntrack table: %v", reflect.TypeOf(key))
		}
	}

	// See doGC4() comment.
	globalDeleteLock[m.mapType].Lock()
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)
	globalDeleteLock[m.mapType].Unlock()
	return stats
}

func purgeCtEntry4(m *Map, key CtKey, entry *CtEntry, natMap *nat.Map) error {
	err := m.Delete(key)
	if err != nil {
		return err
	}

	t := key.GetTupleKey()
	tupleType := t.GetFlags()

	if tupleType == tuple.TUPLE_F_SERVICE && ACT != nil {
		ACT.CountFailed4(entry.RevNAT, uint32(entry.BackendID))
	}

	if natMap == nil {
		return nil
	}

	if tupleType == tuple.TUPLE_F_OUT {
		if entry.isDsrInternalEntry() {
			// To delete NAT entries created by DSR
			nat.DeleteSwappedMapping4(natMap, t.(*tuple.TupleKey4Global))
		} else {
			// To delete NAT entries created for SNAT
			nat.DeleteMapping4(natMap, t.(*tuple.TupleKey4Global))
		}
	}

	return nil
}

// doGC4 iterates through a CTv4 map and drops entries based on the given
// filter.
func doGC4(m *Map, filter *GCFilter) gcStats {
	var natMap *nat.Map

	if m.clusterID == 0 {
		// global map handling
		ctMap := mapInfo[m.mapType]
		if ctMap.natMapLock != nil {
			ctMap.natMapLock.Lock()
			defer ctMap.natMapLock.Unlock()
		}
		natMap = ctMap.natMap
	} else {
		// per-cluster map handling
		natm, err := nat.GetClusterNATMap(m.clusterID, nat.IPv4)
		if err != nil {
			log.WithError(err).Error("Unable to get per-cluster NAT map")
		} else {
			natMap = natm
		}
	}

	stats := statStartGc(m)
	defer stats.finish()

	if natMap != nil {
		if err := natMap.Open(); err == nil {
			defer natMap.Close()
		} else {
			natMap = nil
		}
	}

	filterCallback := func(key bpf.MapKey, value bpf.MapValue) {
		entry := value.(*CtEntry)

		switch obj := key.(type) {
		case *CtKey4Global:
			currentKey4Global := obj
			// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
			// the destination of the packet received, therefore it's the packet's
			// destination IP
			action := filter.doFiltering(currentKey4Global.DestAddr.Addr(), currentKey4Global.SourceAddr.Addr(),
				currentKey4Global.DestPort, currentKey4Global.SourcePort,
				uint8(currentKey4Global.NextHeader), currentKey4Global.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry4(m, currentKey4Global, entry, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey4Global.String()).Error("Unable to delete CT entry")
				} else {
					stats.deleted++
				}
			default:
				stats.aliveEntries++
			}
		case *CtKey4:
			currentKey4 := obj
			// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
			// the destination of the packet received, therefore it's the packet's
			// destination IP
			action := filter.doFiltering(currentKey4.DestAddr.Addr(), currentKey4.SourceAddr.Addr(),
				currentKey4.DestPort, currentKey4.SourcePort,
				uint8(currentKey4.NextHeader), currentKey4.Flags, entry)

			switch action {
			case deleteEntry:
				err := purgeCtEntry4(m, currentKey4, entry, natMap)
				if err != nil {
					log.WithError(err).WithField(logfields.Key, currentKey4.String()).Error("Unable to delete CT entry")
				} else {
					stats.deleted++
				}
			default:
				stats.aliveEntries++
			}
		default:
			log.Warningf("Encountered unknown type while scanning conntrack table: %v", reflect.TypeOf(key))
		}
	}

	// We serialize the deletions in order to avoid forced map walk restarts
	// when keys are being evicted underneath us from concurrent goroutines.
	globalDeleteLock[m.mapType].Lock()
	stats.dumpError = m.DumpReliablyWithCallback(filterCallback, stats.DumpStats)
	globalDeleteLock[m.mapType].Unlock()
	return stats
}

func (f *GCFilter) doFiltering(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, nextHdr, flags uint8, entry *CtEntry) action {
	if f.RemoveExpired && entry.Lifetime < f.Time {
		return deleteEntry
	}
	if f.ValidIPs != nil {
		_, srcIPExists := f.ValidIPs[srcIP]
		_, dstIPExists := f.ValidIPs[dstIP]
		if !srcIPExists && !dstIPExists {
			return deleteEntry
		}
	}

	if f.MatchIPs != nil {
		_, srcIPExists := f.MatchIPs[srcIP]
		_, dstIPExists := f.MatchIPs[dstIP]
		if srcIPExists || dstIPExists {
			return deleteEntry
		}
	}

	if f.EmitCTEntryCB != nil {
		f.EmitCTEntryCB(srcIP, dstIP, srcPort, dstPort, nextHdr, flags, entry)
	}

	return noAction
}

func doGC(m *Map, filter *GCFilter) (int, error) {
	if m.mapType.isIPv6() {
		stats := doGC6(m, filter)
		return int(stats.deleted), stats.dumpError
	} else if m.mapType.isIPv4() {
		stats := doGC4(m, filter)
		return int(stats.deleted), stats.dumpError
	}
	log.Fatalf("Unsupported ct map type: %s", m.mapType.String())
	return 0, fmt.Errorf("unsupported ct map type: %s", m.mapType.String())
}

// GC runs garbage collection for map m with name mapType with the given filter.
// It returns how many items were deleted from m.
func GC(m *Map, filter *GCFilter) (int, error) {
	if filter.RemoveExpired {
		t, _ := timestamp.GetCTCurTime(timestamp.GetClockSourceFromOptions())
		filter.Time = uint32(t)
	}

	return doGC(m, filter)
}

// PurgeOrphanNATEntries removes orphan SNAT entries. We call an SNAT entry
// orphan if it does not have a corresponding CT entry.
//
// Typically NAT entries should get removed along with their owning CT entry,
// as part of purgeCtEntry*(). But stale NAT entries can get left behind if the
// CT entry disappears for other reasons - for instance by LRU eviction, or
// when the datapath re-purposes the CT entry.
//
// PurgeOrphanNATEntries() is triggered by the datapath via the GC signaling
// mechanism. When the datapath SNAT fails to find free mapping after
// SNAT_SIGNAL_THRES attempts, it sends the signal via the perf ring buffer.
// The consumer of the buffer invokes the function.
//
// The SNAT is being used for the following cases:
//  1. By NodePort BPF on an intermediate node before fwd'ing request from outside
//     to a destination node.
//  2. A packet from local endpoint sent to outside (BPF-masq).
//  3. A packet from a host local application (i.e. running in the host netns)
//     This is needed to prevent SNAT from hijacking such connections.
//  4. By DSR on a backend node to SNAT responses with service IP+port before
//     sending to a client.
//
// In all 4 cases we create a CT_EGRESS CT entry. This allows the
// CT GC to remove corresponding SNAT entries.
// See the unit test TestOrphanNatGC for more examples.
func PurgeOrphanNATEntries(ctMapTCP, ctMapAny *Map) *NatGCStats {
	// Both CT maps should point to the same natMap, so use the first one
	// to determine natMap
	ctMap := mapInfo[ctMapTCP.mapType]
	if ctMap.natMapLock != nil {
		ctMap.natMapLock.Lock()
		defer ctMap.natMapLock.Unlock()
	}
	natMap := ctMap.natMap
	if natMap == nil {
		return nil
	}

	family := gcFamilyIPv4
	if ctMapTCP.mapType.isIPv6() {
		family = gcFamilyIPv6
	}
	stats := newNatGCStats(natMap, family)
	defer stats.finish()

	cb := func(key bpf.MapKey, value bpf.MapValue) {
		natKey := key.(nat.NatKey)
		natVal := value.(nat.NatEntry)

		ctMap := ctMapAny
		if natKey.GetNextHeader() == u8proto.TCP {
			ctMap = ctMapTCP
		}

		if natKey.GetFlags()&tuple.TUPLE_F_IN == tuple.TUPLE_F_IN { // natKey is r(everse)tuple
			ctKey := egressCTKeyFromIngressNatKeyAndVal(natKey, natVal)

			if !ctEntryExist(ctMap, ctKey, nil) {
				// No egress CT entry is found, delete the orphan ingress SNAT entry
				if deleted, _ := natMap.Delete(natKey); deleted {
					stats.IngressDeleted++
				}
			} else {
				stats.IngressAlive++
			}
		} else if natKey.GetFlags()&tuple.TUPLE_F_OUT == tuple.TUPLE_F_OUT {
			checkDsr := func(entry *CtEntry) bool {
				return entry.isDsrInternalEntry()
			}

			egressCTKey := egressCTKeyFromEgressNatKey(natKey)
			dsrCTKey := dsrCTKeyFromEgressNatKey(natKey)

			if !ctEntryExist(ctMap, egressCTKey, nil) &&
				!ctEntryExist(ctMap, dsrCTKey, checkDsr) {
				// No relevant CT entries were found, delete the orphan egress NAT entry
				if deleted, _ := natMap.Delete(natKey); deleted {
					stats.EgressDeleted++
				}
			} else {
				stats.EgressAlive++
			}
		}
	}

	if err := natMap.DumpReliablyWithCallback(cb, stats.DumpStats); err != nil {
		log.WithError(err).Error("NATmap dump failed during GC")
	} else {
		natMap.UpdatePressureMetricWithSize(int32(stats.IngressAlive + stats.EgressAlive))
	}

	return &stats
}

// Flush runs garbage collection for map m with the name mapType, deleting all
// entries. The specified map must be already opened using bpf.OpenMap().
func (m *Map) Flush() int {
	d, _ := doGC(m, &GCFilter{
		RemoveExpired: true,
		Time:          MaxTime,
	})
	return d
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

		// Pass nil key and value types since we're not intending on accessing the
		// map's contents.
		oldMap, err := bpf.OpenMap(path, nil, nil)
		if err != nil {
			scopedLog.WithError(err).Debug("Couldn't open CT map for upgrade")
			continue
		}
		defer oldMap.Close()

		if oldMap.CheckAndUpgrade(&newMap.Map) {
			scopedLog.Warning("CT Map upgraded, expect brief disruption of ongoing connections")
		}
	}
}

// maps returns all connecting tracking maps associated with endpoint 'e' (or
// the global maps if 'e' is nil).
func maps(e CtEndpoint, ipv4, ipv6 bool) []*Map {
	result := make([]*Map, 0, mapCount)
	if e == nil {
		if ipv4 {
			result = append(result, newMap(MapNameTCP4Global, mapTypeIPv4TCPGlobal))
			result = append(result, newMap(MapNameAny4Global, mapTypeIPv4AnyGlobal))
		}
		if ipv6 {
			result = append(result, newMap(MapNameTCP6Global, mapTypeIPv6TCPGlobal))
			result = append(result, newMap(MapNameAny6Global, mapTypeIPv6AnyGlobal))
		}
	} else {
		if ipv4 {
			result = append(result, newMap(bpf.LocalMapName(MapNameTCP4, uint16(e.GetID())),
				mapTypeIPv4TCPLocal))
			result = append(result, newMap(bpf.LocalMapName(MapNameAny4, uint16(e.GetID())),
				mapTypeIPv4AnyLocal))
		}
		if ipv6 {
			result = append(result, newMap(bpf.LocalMapName(MapNameTCP6, uint16(e.GetID())),
				mapTypeIPv6TCPLocal))
			result = append(result, newMap(bpf.LocalMapName(MapNameAny6, uint16(e.GetID())),
				mapTypeIPv6AnyLocal))
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
			mapEntriesTCP = m.mapType.maxEntries()
		} else {
			mapEntriesAny = m.mapType.maxEntries()
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

var cachedGCInterval time.Duration

// GetInterval returns the interval adjusted based on the deletion ratio of the
// last run
func GetInterval(actualPrevInterval time.Duration, maxDeleteRatio float64) time.Duration {
	if val := option.Config.ConntrackGCInterval; val != time.Duration(0) {
		return val
	}

	expectedPrevInterval := cachedGCInterval
	adjustedDeleteRatio := maxDeleteRatio
	if expectedPrevInterval == time.Duration(0) {
		expectedPrevInterval = defaults.ConntrackGCStartingInterval
	} else if actualPrevInterval < expectedPrevInterval && actualPrevInterval > 0 {
		adjustedDeleteRatio *= float64(expectedPrevInterval) / float64(actualPrevInterval)
	}

	newInterval := calculateInterval(expectedPrevInterval, adjustedDeleteRatio)
	if val := option.Config.ConntrackGCMaxInterval; val != time.Duration(0) && newInterval > val {
		newInterval = val
	}

	if newInterval != expectedPrevInterval {
		log.WithFields(logrus.Fields{
			"expectedPrevInterval": expectedPrevInterval,
			"actualPrevInterval":   actualPrevInterval,
			"newInterval":          newInterval,
			"deleteRatio":          maxDeleteRatio,
			"adjustedDeleteRatio":  adjustedDeleteRatio,
		}).Info("Conntrack garbage collector interval recalculated")
	}

	return newInterval
}

func calculateInterval(prevInterval time.Duration, maxDeleteRatio float64) (interval time.Duration) {
	interval = prevInterval

	if maxDeleteRatio == 0.0 {
		return
	}

	switch {
	case maxDeleteRatio > 0.25:
		if maxDeleteRatio > 0.9 {
			maxDeleteRatio = 0.9
		}
		// 25%..90% => 1.3x..10x shorter
		interval = time.Duration(float64(interval) * (1.0 - maxDeleteRatio)).Round(time.Second)

		if interval < defaults.ConntrackGCMinInterval {
			interval = defaults.ConntrackGCMinInterval
		}

	case maxDeleteRatio < 0.05:
		// When less than 5% of entries were deleted, increase the
		// interval. Use a simple 1.5x multiplier to start growing slowly
		// as a new node may not be seeing workloads yet and thus the
		// scan will return a low deletion ratio at first.
		interval = time.Duration(float64(interval) * 1.5).Round(time.Second)
		if interval > defaults.ConntrackGCMaxLRUInterval {
			interval = defaults.ConntrackGCMaxLRUInterval
		}
	}

	cachedGCInterval = interval

	return
}

// CalculateCTMapPressure is a controller that calculates the BPF CT map
// pressure and pubishes it as part of the BPF map pressure metric.
func CalculateCTMapPressure(mgr *controller.Manager, allMaps ...*Map) {
	ctx, cancel := context.WithCancelCause(context.Background())
	mgr.UpdateController("ct-map-pressure", controller.ControllerParams{
		Group: controller.Group{
			Name: "ct-map-pressure",
		},
		DoFunc: func(context.Context) error {
			var errs error
			for _, m := range allMaps {
				path, err := OpenCTMap(m)
				if err != nil {
					msg := "Skipping CT map pressure calculation"
					scopedLog := log.WithError(err).WithField(logfields.Path, path)
					if os.IsNotExist(err) {
						scopedLog.Debug(msg)
					} else {
						scopedLog.Warn(msg)
					}
					continue
				}
				defer m.Close()

				count, err := m.Count()
				if errors.Is(err, ebpf.ErrNotSupported) {
					// We don't have batch ops, so cancel context to kill this
					// controller.
					cancel(err)
					return err
				}
				if err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to dump CT map %v: %w", m.Name(), err))
				}
				m.UpdatePressureMetricWithSize(int32(count))
			}
			return errs
		},
		RunInterval: 30 * time.Second,
		Context:     ctx,
	})
}
