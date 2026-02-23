// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/timestamp"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
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
	DumpEntriesWithTimeDiff(clockSource *models.ClockSource) (string, error)
	DumpWithCallback(bpf.DumpCallback) error
	Count(context.Context) (int, error)
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
func InitMapInfo(nat4 nat.NatMap4, nat6 nat.NatMap6) {
	var global4Map, global6Map *nat.Map
	global4MapLock := &lock.Mutex{}
	global6MapLock := &lock.Mutex{}

	if nat4 != nil {
		if m, ok := nat4.(*nat.Map); ok && m != nil {
			global4Map = m
		}
	}
	if nat6 != nil {
		if m, ok := nat6.(*nat.Map); ok && m != nil {
			global6Map = m
		}
	}

	mapInfo = map[mapType]mapAttributes{
		mapTypeIPv4TCPGlobal: {natMap: global4Map, natMapLock: global4MapLock},
		mapTypeIPv6TCPGlobal: {natMap: global6Map, natMapLock: global6MapLock},
		mapTypeIPv4AnyGlobal: {natMap: global4Map, natMapLock: global4MapLock},
		mapTypeIPv6AnyGlobal: {natMap: global6Map, natMapLock: global6MapLock},
	}
}

// Map represents an instance of a BPF connection tracking map.
// It also implements the CtMap interface.
type Map struct {
	bpf.Map

	mapType mapType

	// This field indicates which cluster this ctmap is. Zero for global
	// maps and non-zero for per-cluster maps.
	clusterID uint32

	// networkID indicates what network this connection tracking map
	// belongs to. IPs from different networks may overlap.
	// The default network has ID zero.
	// Maps which have this non-zero are assumed to not have a
	// corresponding NAT map.
	networkID uint32
}

// NetAddr is an IP address that belongs to a particular network
type NetAddr struct {
	Addr  netip.Addr
	NetID uint32
}

// GCFilter contains the necessary fields to filter the CT maps.
type GCFilter struct {
	// RemoveExpired enables removal of all entries that have expired
	RemoveExpired bool

	// Time is the reference timestamp to remove expired entries. If
	// RemoveExpired is true and lifetime is lesser than Time, the entry is
	// removed
	Time uint32

	// MatchIPs is the list of IPs to remove from the conntrack table
	MatchIPs map[NetAddr]struct{}

	// EmitCTEntry is called, when non-nil, if filtering by ValidIPs and MatchIPs
	// passes. It has no impact on CT GC, but can be used to iterate over valid
	// CT entries.
	EmitCTEntryCB EmitCTEntryCBFunc
}

// EmitCTEntryCBFunc is the type used for the EmitCTEntryCB callback in GCFilter
type EmitCTEntryCBFunc func(srcIP, dstIP NetAddr, srcPort, dstPort uint16, nextHdr, flags uint8, entry *CtEntry)

// TODO: GH-33557: Remove this hack once ctmap is migrated to a cell.
type PurgeHook interface {
	CountFailed4(uint16, uint32)
	CountFailed6(uint16, uint32)
}

var ACT PurgeHook

type GCEvent struct {
	Key    CtKey
	Entry  *CtEntry
	NatMap *nat.Map
}

type MapPair struct {
	TCP *Map
	Any *Map
}

type natDeleteFunc func(natMap *nat.Map, key tuple.TupleKey) error

func NatMapNext4(event GCEvent) {
	natMapNext(
		event,
		nat.DeleteMapping4,
		nat.DeleteSwappedMapping4,
	)
}

func NatMapNext6(event GCEvent) {
	natMapNext(
		event,
		nat.DeleteMapping6,
		nat.DeleteSwappedMapping6,
	)
}

func natMapNext(event GCEvent, deleteMapping natDeleteFunc, deleteSwappedMapping natDeleteFunc) {
	if event.NatMap == nil {
		return
	}

	t := event.Key.GetTupleKey()
	tupleType := t.GetFlags()

	if tupleType == tuple.TUPLE_F_OUT {
		// Check if the entry is for DSR and call the appropriate delete function
		if event.Entry.isDsrInternalEntry() {
			deleteSwappedMapping(event.NatMap, t)
		} else {
			deleteMapping(event.NatMap, t)
		}
	}
}

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

// DumpEntriesWithTimeDiff iterates through Map m and writes the values of the ct entries
// in m to a string.
func (m *Map) DumpEntriesWithTimeDiff(clockSource *models.ClockSource) (string, error) {
	return DumpEntriesWithTimeDiff(m, clockSource)
}

// Count batch dumps the Map m and returns the count of the entries.
func (m *Map) Count(ctx context.Context) (count int, err error) {
	if m.mapType.isIPv4() {
		iter := bpf.NewBatchIterator[tuple.TupleKey4, CtEntry](&m.Map)
		return bpf.CountAll(ctx, iter)
	} else {
		iter := bpf.NewBatchIterator[tuple.TupleKey6, CtEntry](&m.Map)
		return bpf.CountAll(ctx, iter)
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

type MapOption func(*Map)

// WithRegistry enables pressure metrics for this CT map
func WithRegistry(registry *metrics.Registry) MapOption {
	return func(m *Map) {
		m.Map.WithPressureMetric(registry)
	}
}

// WithNetworkID marks this CT map as belonging to a particular network
func WithNetworkID(networkID uint32) MapOption {
	return func(m *Map) {
		m.networkID = networkID
	}
}

// WithClusterID marks this CT map as belonging to a particular cluster
func WithClusterID(clusterID uint32) MapOption {
	return func(m *Map) {
		m.clusterID = clusterID
	}
}

type MapConfig struct {
	IPv6 bool
	TCP  bool
}

// NewGlobalMap allows the creation of additional global CT map.
// This is intended to be used to register additional CT maps for GC with gc.AdditionalCTMapsFunc.
func NewGlobalMap(name string, cfg MapConfig, opts ...MapOption) *Map {
	var newMapType mapType
	switch {
	case cfg.IPv6 && cfg.TCP:
		newMapType = mapTypeIPv6TCPGlobal
	case cfg.IPv6 && !cfg.TCP:
		newMapType = mapTypeIPv6AnyGlobal
	case !cfg.IPv6 && cfg.TCP:
		newMapType = mapTypeIPv4TCPGlobal
	case !cfg.IPv6 && !cfg.TCP:
		newMapType = mapTypeIPv4AnyGlobal
	}
	return newMap(name, newMapType, opts...)
}

// newMap creates a new CT map of the specified type with the specified name.
func newMap(mapName string, m mapType, opts ...MapOption) *Map {
	result := &Map{
		Map: *bpf.NewMap(mapName,
			ebpf.LRUHash,
			m.key(),
			m.value(),
			m.maxEntries(),
			0,
		),
		mapType: m,
	}
	for _, opt := range opts {
		opt(result)
	}

	return result
}

// doGCForFamily iterates through a CTv6 map and drops entries based on the given
// filter.
func (m *Map) doGCForFamily(filter GCFilter, next4, next6 func(GCEvent), ipv6 bool) gcStats {
	family := nat.IPv4
	if ipv6 {
		family = nat.IPv6
	}

	var natMap *nat.Map

	if m.clusterID == 0 && m.networkID == 0 {
		// global map handling
		ctMap := mapInfo[m.mapType]
		if ctMap.natMapLock != nil {
			ctMap.natMapLock.Lock()
			defer ctMap.natMapLock.Unlock()
		}
		natMap = ctMap.natMap
	} else if m.networkID == 0 {
		// per-cluster map handling
		natm, err := nat.GetClusterNATMap(m.clusterID, family)
		if err != nil {
			m.Logger.Error("Unable to get per-cluster NAT map", logfields.Error, err)
		} else {
			natMap = natm
			err := natMap.Open()
			if err != nil {
				m.Logger.Error("Unable to open per-cluster NAT map", logfields.Error, err)
				natMap = nil
			} else {
				defer natMap.Close()
			}
		}
	}

	stats := statStartGc(m)
	defer stats.finish()

	// We serialize the deletions in order to avoid forced map walk restarts
	// when keys are being evicted underneath us from concurrent goroutines.
	// Thus globalDeleteLock must be held while performing cleanip sweep
	// otherwise (*Endpoint).scrubIPsInConntrackTableLocked() may cause deletes
	// to happen concurrently.
	globalDeleteLock[m.mapType].Lock()
	if ipv6 {
		filterCallback := m.cleanup(filter, natMap, &stats, next6, ipv6)
		stats.dumpError = iterate[CtKey6Global, CtEntry](m, &stats, filterCallback)
	} else {
		filterCallback := m.cleanup(filter, natMap, &stats, next4, ipv6)
		stats.dumpError = iterate[CtKey4Global, CtEntry](m, &stats, filterCallback)
	}
	globalDeleteLock[m.mapType].Unlock()

	return stats
}

func (m *Map) purgeCtEntry(key CtKey, entry *CtEntry, natMap *nat.Map, next func(event GCEvent), actCountFailed func(uint16, uint32)) error {
	err := m.DeleteLocked(key)
	if err != nil {
		return err
	}

	t := key.GetTupleKey()
	tupleType := t.GetFlags()

	if tupleType == tuple.TUPLE_F_SERVICE && ACT != nil {
		actCountFailed(entry.RevNAT, uint32(entry.Union0[1]))
	}

	next(GCEvent{
		Key:    key,
		Entry:  entry,
		NatMap: natMap,
	})

	return nil
}

func iterate[KT any, VT any, KP bpf.KeyPointer[KT], VP bpf.ValuePointer[VT]](m *Map, stats *gcStats, filterCallback func(key bpf.MapKey, value bpf.MapValue)) error {
	ctx := context.Background()
	iter := bpf.NewBatchIterator[KT, VT, KP, VP](&m.Map)
	for k, v := range iter.IterateAll(ctx) {
		filterCallback(k, v)
	}
	stats.Completed = true
	return iter.Err()
}

var _ tupleKeyAccessor = &tuple.TupleKey4{}

var _ tupleKeyAccessor = &tuple.TupleKey6{}

type tupleKeyAccessor interface {
	GetDestAddr() netip.Addr
	GetDestPort() uint16
	GetSourceAddr() netip.Addr
	GetSourcePort() uint16
	GetNextHeader() u8proto.U8proto
	GetFlags() uint8
}

func (m *Map) cleanup(filter GCFilter, natMap *nat.Map, stats *gcStats, next func(GCEvent), ipv6 bool) func(key bpf.MapKey, value bpf.MapValue) {
	var countFailedFn func(uint16, uint32)
	if ACT != nil {
		countFailedFn = ACT.CountFailed4
		if ipv6 {
			countFailedFn = ACT.CountFailed6
		}
	}
	return func(key bpf.MapKey, value bpf.MapValue) {
		// TODO: These type assertions are a bit dangerous, make more of this well typed
		// to avoid having to make these assertions.
		tupleKey := key.(tupleKeyAccessor)
		ctKey := key.(CtKey)
		entry := value.(*CtEntry)

		// In CT entries, the source address of the conntrack entry (`SourceAddr`) is
		// the destination of the packet received, therefore it's the packet's
		// destination IP
		srcIP := NetAddr{Addr: tupleKey.GetDestAddr(), NetID: m.networkID}
		dstIP := NetAddr{Addr: tupleKey.GetSourceAddr(), NetID: m.networkID}
		action := filter.doFiltering(srcIP, dstIP,
			tupleKey.GetDestPort(), tupleKey.GetSourcePort(),
			uint8(tupleKey.GetNextHeader()), tupleKey.GetFlags(), entry)

		switch action {
		case deleteEntry:
			err := m.purgeCtEntry(ctKey, entry, natMap, next, countFailedFn)
			if err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					m.Logger.Debug("key is missing, likely due to lru eviction - skipping",
						logfields.Error, err,
						logfields.Key, ctKey.ToHost(),
					)
					stats.skipped++
				} else {
					m.Logger.Error("key is missing, likely due to lru eviction - skipping",
						logfields.Error, err,
						logfields.Key, ctKey.ToHost(),
					)
				}
			} else {
				stats.deleted++
			}
		default:
			stats.aliveEntries++
		}
	}
}

func (f GCFilter) doFiltering(srcIP, dstIP NetAddr, srcPort, dstPort uint16, nextHdr, flags uint8, entry *CtEntry) action {
	if f.RemoveExpired && entry.Lifetime < f.Time {
		return deleteEntry
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

func (m *Map) doGC(filter GCFilter, next4, next6 func(GCEvent)) (int, error) {
	stats := m.doGCForFamily(filter, next4, next6, m.mapType.isIPv6())
	return int(stats.deleted), stats.dumpError
}

// GC runs garbage collection for map m with name mapType with the given filter.
// It returns how many items were deleted from m.
func (m *Map) GC(filter GCFilter, next4, next6 func(GCEvent)) (int, error) {
	if filter.RemoveExpired {
		t, _ := timestamp.GetCTCurTime(timestamp.GetClockSourceFromOptions())
		filter.Time = uint32(t)
	}

	return m.doGC(filter, next4, next6)
}

// PurgeOrphanNATEntries removes orphan SNAT entries. We call an SNAT entry
// orphan if it does not have a corresponding CT entry.
//
// Typically NAT entries should get removed along with their owning CT entry,
// as part of purgeCtEntry(). But stale NAT entries can get left behind if the
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
// See the unit test TestPrivilegedOrphanNatGC for more examples.
func PurgeOrphanNATEntries(ctMapTCP, ctMapAny *Map) *NatGCStats {
	var natMap *nat.Map

	// Both CT maps should point to the same natMap, so use the first one
	// to determine natMap
	if ctMapTCP.clusterID == 0 && ctMapTCP.networkID == 0 {
		// global map handling
		ctMap := mapInfo[ctMapTCP.mapType]
		if ctMap.natMapLock != nil {
			ctMap.natMapLock.Lock()
			defer ctMap.natMapLock.Unlock()
		}
		natMap = ctMap.natMap
	} else if ctMapTCP.networkID == 0 {
		// per-cluster map handling
		family := nat.IPv4
		if ctMapTCP.mapType.isIPv6() {
			family = nat.IPv6
		}

		natm, err := nat.GetClusterNATMap(ctMapTCP.clusterID, family)
		if err != nil {
			ctMapTCP.Logger.Error("Unable to get per-cluster NAT map", logfields.Error, err)
		} else {
			natMap = natm
		}

		if natMap != nil {
			if err := natMap.Open(); err != nil {
				natMap.Logger.Error("Unable to open per-cluster NAT map", logfields.Error, err)
				return nil
			}
			defer natMap.Close()
		}
	}

	if natMap == nil {
		return nil
	}

	family := gcFamilyIPv4
	if ctMapTCP.mapType.isIPv6() {
		family = gcFamilyIPv6
	}
	stats := newNatGCStats(natMap, family, ctMapTCP.clusterID)
	defer stats.finish()
	egressEntriesToDelete := make([]nat.NatKey, 0)
	ingressEntriesToDelete := make([]nat.NatKey, 0)

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
				ingressEntriesToDelete = append(ingressEntriesToDelete, natKey)
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
				egressEntriesToDelete = append(egressEntriesToDelete, natKey)
			} else {
				stats.EgressAlive++
			}
		}
	}

	if err := natMap.DumpReliablyWithCallback(cb, stats.DumpStats); err != nil {
		natMap.Logger.Error("NATmap dump failed during GC", logfields.Error, err)
	} else {
		for _, key := range egressEntriesToDelete {
			if deleted, _ := natMap.Delete(key); deleted {
				stats.EgressDeleted++
			}
		}
		for _, key := range ingressEntriesToDelete {
			if deleted, _ := natMap.Delete(key); deleted {
				stats.IngressDeleted++
			}
		}
		natMap.UpdatePressureMetricWithSize(int32(stats.IngressAlive + stats.EgressAlive))
	}

	return &stats
}

// Flush runs garbage collection for map m with the name mapType, deleting all
// entries. The specified map must be already opened using bpf.OpenMap().
func (m *Map) Flush(next4, next6 func(GCEvent)) int {
	d, _ := m.doGC(GCFilter{
		RemoveExpired: true,
		Time:          MaxTime,
	}, next4, next6)

	return d
}

// Maps returns a slice of all CT maps that are used.
// If ipv4 or ipv6 are false, the maps for that protocol will not be returned.
//
// The returned maps are not yet opened.
//
// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
func Maps(ipv4, ipv6 bool) []*Map {
	result := make([]*Map, 0, mapCount)
	if ipv4 {
		result = append(result, newMap(MapNameTCP4Global, mapTypeIPv4TCPGlobal))
		result = append(result, newMap(MapNameAny4Global, mapTypeIPv4AnyGlobal))
	}
	if ipv6 {
		result = append(result, newMap(MapNameTCP6Global, mapTypeIPv6TCPGlobal))
		result = append(result, newMap(MapNameAny6Global, mapTypeIPv6AnyGlobal))
	}
	return result
}
