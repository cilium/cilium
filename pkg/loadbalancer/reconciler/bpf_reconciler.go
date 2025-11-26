// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/byteorder"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

func newBPFReconciler(p reconciler.Params, g job.Group, cfg loadbalancer.Config, ops *BPFOps, fes statedb.Table[*loadbalancer.Frontend], w *writer.Writer) (reconciler.Reconciler[*loadbalancer.Frontend], error) {
	if !w.IsEnabled() {
		return nil, nil
	}

	// Use a custom lifecycle to start the reconciler so we can delay it starts until tables are initialized.
	rlc := &cell.DefaultLifecycle{}
	started := make(chan struct{})
	p.Lifecycle.Append(cell.Hook{
		OnStop: func(ctx cell.HookContext) error {
			// Since starting happens asynchronously, wait for it to be done before trying to stop.
			select {
			case <-ctx.Done():
			case <-started:
			}
			return rlc.Stop(p.Log, ctx)
		},
	})
	p.Lifecycle = rlc

	r, err := reconciler.Register(
		p,
		fes.(statedb.RWTable[*loadbalancer.Frontend]),

		(*loadbalancer.Frontend).Clone,
		func(fe *loadbalancer.Frontend, s reconciler.Status) *loadbalancer.Frontend {
			fe.Status = s
			return fe
		},
		func(fe *loadbalancer.Frontend) reconciler.Status {
			return fe.Status
		},
		ops,
		nil,

		reconciler.WithRetry(
			cfg.RetryBackoffMin,
			cfg.RetryBackoffMax,
		),

		reconciler.WithPruning(
			30*time.Minute,
		),
	)

	g.Add(
		job.OneShot("start-reconciler", func(ctx context.Context, health cell.Health) error {
			defer close(started)

			if len(ops.restoredServiceIDs) > 0 {
				// We give a short grace period for initializers to finish populating the initial contents
				// of the tables to avoid scaling down load-balancing due to e.g. seeing backends from k8s
				// much earlier than from ClusterMesh for the same service.
				//
				// We only do this if we restored data from BPF maps as only in that scenario we could
				// be scaling down. This way we also don't introduce an unnecessary delay to connecting
				// to the ClusterMesh api-server if it connects via a k8s service.
				health.OK("Waiting for load-balancing tables to initialize")
				_, initWatch := w.Frontends().Initialized(p.DB.ReadTxn())
				select {
				case <-ctx.Done():
					return nil
				case <-initWatch:
				case <-time.After(cfg.InitWaitTimeout):
					p.Log.Warn("Timed out waiting for load-balancing state to initialize, proceeding with reconciliation")
				}
			}

			health.OK("Starting")
			if err := rlc.Start(p.Log, ctx); err != nil {
				return err
			}
			health.OK("Started")
			return nil
		}),
	)

	return r, err
}

type BPFOps struct {
	LBMaps    maps.LBMaps
	log       rateLimitingLogger
	db        *statedb.DB
	nodeAddrs statedb.Table[tables.NodeAddress]

	cfg           loadbalancer.Config
	extCfg        loadbalancer.ExternalConfig
	maglev        *maglev.Maglev
	lastUpdatedAt atomic.Pointer[time.Time]
	pruneCount    atomic.Int32

	// mu protects the state below. The reconciler itself is single-threaded, but we need
	// to protect the state in order to be able to ResetAndRestore() in tests.
	mu lock.Mutex

	serviceIDAlloc     idAllocator[loadbalancer.ServiceID]
	restoredServiceIDs map[loadbalancer.L3n4Addr]loadbalancer.ServiceID
	backendIDAlloc     idAllocator[loadbalancer.BackendID]
	restoredBackendIDs map[loadbalancer.L3n4Addr]loadbalancer.BackendID

	// restoredQuarantinedBackends are backends that were quarantined for
	// a specific frontend. This comes into play when we have active health checker.
	// On restart we restore this information and use this until we get an update
	// from a health checker ([Backend.UnhealthyUpdatedAt] is non-zero).
	restoredQuarantinedBackends map[loadbalancer.L3n4Addr]sets.Set[loadbalancer.L3n4Addr]

	// backendStates maps from backend address to associated state.
	// This is used to track which frontends reference a specific backend
	// in order to delete orphaned backeds.
	backendStates map[loadbalancer.L3n4Addr]backendState

	// backendReferences maps from frontend address to the set of referenced
	// backends.
	backendReferences map[loadbalancer.L3n4Addr]sets.Set[loadbalancer.L3n4Addr]

	// prevSourceRanges is the source ranges that were previously reconciled.
	// This is used when updating to remove orphans.
	prevSourceRanges map[loadbalancer.L3n4Addr]sets.Set[netip.Prefix]

	// nodePortAddrByPort are the last used NodePort addresses for a given NodePort
	// (or HostPort) service (by port).
	nodePortAddrByPort map[nodePortAddrKey][]netip.Addr
}

type nodePortAddrKey struct {
	// family is Address Family of the key
	family loadbalancer.IPFamily

	// protocol is the Layer 4 protocol number of the key
	protocol u8proto.U8proto

	// port is the Layer 4 port number of the key
	port uint16
}

type backendState struct {
	addr     loadbalancer.L3n4Addr
	revision statedb.Revision
	refCount int
	id       loadbalancer.BackendID
}

type bpfOpsParams struct {
	cell.In

	Lifecycle      cell.Lifecycle
	Log            *slog.Logger
	Config         loadbalancer.Config
	ExternalConfig loadbalancer.ExternalConfig
	LBMaps         maps.LBMaps
	Maglev         *maglev.Maglev
	DB             *statedb.DB
	NodeAddresses  statedb.Table[tables.NodeAddress]
}

const (
	logfieldActiveCount      = "active-count"
	logfieldTerminatingCount = "terminating-count"
	logfieldInactiveCount    = "inactive-count"
)

func newBPFOps(p bpfOpsParams) *BPFOps {
	ops := &BPFOps{
		cfg:       p.Config,
		extCfg:    p.ExternalConfig,
		maglev:    p.Maglev,
		log:       newRateLimitingLogger(p.Log),
		LBMaps:    p.LBMaps,
		db:        p.DB,
		nodeAddrs: p.NodeAddresses,
	}
	ops.setLastUpdatedAt()

	p.Lifecycle.Append(cell.Hook{OnStart: ops.start})
	return ops
}

func (ops *BPFOps) GetLastUpdatedAt() time.Time {
	return *ops.lastUpdatedAt.Load()
}

func (ops *BPFOps) setLastUpdatedAt() {
	now := time.Now()
	ops.lastUpdatedAt.Store(&now)
}

func (ops *BPFOps) start(cell.HookContext) (err error) {
	return ops.ResetAndRestore()
}

func (ops *BPFOps) ResetAndRestore() (err error) {
	ops.mu.Lock()
	defer ops.mu.Unlock()

	ops.serviceIDAlloc = newIDAllocator(firstFreeServiceID, maxSetOfServiceID)
	ops.restoredServiceIDs = map[loadbalancer.L3n4Addr]loadbalancer.ServiceID{}
	ops.backendIDAlloc = newIDAllocator(firstFreeBackendID, maxSetOfBackendID)
	ops.restoredBackendIDs = map[loadbalancer.L3n4Addr]loadbalancer.BackendID{}
	ops.backendStates = map[loadbalancer.L3n4Addr]backendState{}
	ops.backendReferences = map[loadbalancer.L3n4Addr]sets.Set[loadbalancer.L3n4Addr]{}
	ops.nodePortAddrByPort = map[nodePortAddrKey][]netip.Addr{}
	ops.prevSourceRanges = map[loadbalancer.L3n4Addr]sets.Set[netip.Prefix]{}

	// Restore backend IDs
	backendIDToAddress := map[loadbalancer.BackendID]loadbalancer.L3n4Addr{}
	err = ops.LBMaps.DumpBackend(func(key maps.BackendKey, value maps.BackendValue) {
		value = value.ToHost()
		addr := beValueToAddr(value)
		backendIDToAddress[key.GetID()] = addr
		if addr.Protocol() == loadbalancer.ANY {
			// Migrate from 'ANY' protocol by reusing the ID.
			addr2 := loadbalancer.NewL3n4Addr(loadbalancer.TCP, addr.AddrCluster(), addr.Port(), addr.Scope())
			ops.restoredBackendIDs[addr2] = key.GetID()
			addr2 = loadbalancer.NewL3n4Addr(loadbalancer.UDP, addr.AddrCluster(), addr.Port(), addr.Scope())
			ops.restoredBackendIDs[addr2] = key.GetID()
			addr2 = loadbalancer.NewL3n4Addr(loadbalancer.SCTP, addr.AddrCluster(), addr.Port(), addr.Scope())
			ops.restoredBackendIDs[addr2] = key.GetID()
		} else {
			ops.restoredBackendIDs[addr] = key.GetID()
		}
		ops.backendIDAlloc.nextID = max(ops.backendIDAlloc.nextID, key.GetID()+1)
	})
	if err != nil {
		return fmt.Errorf("restore backend ids: %w", err)
	}

	// Gather all services key'd by address.
	serviceSlots := map[loadbalancer.L3n4Addr][]maps.ServiceValue{}
	err = ops.LBMaps.DumpService(func(key maps.ServiceKey, value maps.ServiceValue) {
		key = key.ToHost()
		value = value.ToHost()
		addr := svcKeyToAddr(key)
		s := slices.Grow(serviceSlots[addr], key.GetBackendSlot()+1)
		s = s[:max(len(s), key.GetBackendSlot()+1)]
		s[key.GetBackendSlot()] = value
		serviceSlots[addr] = s
	})
	if err != nil {
		return fmt.Errorf("restore service ids: %w", err)
	}

	for addr, slots := range serviceSlots {
		// Restore the ID allocations from the BPF maps in order to reuse
		// them and thus avoiding traffic disruptions.
		master := slots[0]
		if master == nil {
			continue
		}

		id := loadbalancer.ServiceID(master.GetRevNat())

		if addr.Protocol() == loadbalancer.ANY {
			// Migrate from 'ANY' protocol by reusing the ID.
			addr2 := loadbalancer.NewL3n4Addr(loadbalancer.TCP, addr.AddrCluster(), addr.Port(), addr.Scope())
			ops.restoredServiceIDs[addr2] = id
			addr2 = loadbalancer.NewL3n4Addr(loadbalancer.UDP, addr.AddrCluster(), addr.Port(), addr.Scope())
			ops.restoredServiceIDs[addr2] = id
			addr2 = loadbalancer.NewL3n4Addr(loadbalancer.SCTP, addr.AddrCluster(), addr.Port(), addr.Scope())
			ops.restoredServiceIDs[addr2] = id
		} else {
			ops.restoredServiceIDs[addr] = id
		}
		ops.serviceIDAlloc.nextID = max(ops.serviceIDAlloc.nextID, id+1)

		if master.GetQCount() > 0 && len(slots) == 1+master.GetCount()+master.GetQCount() {
			if ops.restoredQuarantinedBackends == nil {
				ops.restoredQuarantinedBackends = make(map[loadbalancer.L3n4Addr]sets.Set[loadbalancer.L3n4Addr])
			}
			backends := ops.restoredQuarantinedBackends[addr]
			if backends == nil {
				backends = sets.New[loadbalancer.L3n4Addr]()
				ops.restoredQuarantinedBackends[addr] = backends
			}
			for _, slot := range slots[1+master.GetCount():] {
				if addr, found := backendIDToAddress[slot.GetBackendID()]; found {
					backends.Insert(addr)
				}
			}
		}
	}
	return nil
}

func svcKeyToAddr(svcKey maps.ServiceKey) loadbalancer.L3n4Addr {
	feIP := svcKey.GetAddress()
	feAddrCluster := cmtypes.MustAddrClusterFromIP(feIP)
	proto := loadbalancer.NewL4TypeFromNumber(svcKey.GetProtocol())
	feL3n4Addr := loadbalancer.NewL3n4Addr(proto, feAddrCluster, svcKey.GetPort(), svcKey.GetScope())
	return feL3n4Addr
}

func beValueToAddr(beValue maps.BackendValue) loadbalancer.L3n4Addr {
	beAddrCluster := beValue.GetAddress()
	proto := loadbalancer.NewL4TypeFromNumber(beValue.GetProtocol())
	beL3n4Addr := loadbalancer.NewL3n4Addr(proto, beAddrCluster, beValue.GetPort(), 0)
	return beL3n4Addr
}

// Delete implements reconciler.Operations.
func (ops *BPFOps) Delete(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, fe *loadbalancer.Frontend) error {
	ops.mu.Lock()
	defer ops.mu.Unlock()
	defer ops.setLastUpdatedAt()

	if (!ops.extCfg.EnableIPv6 && fe.Address.IsIPv6()) || (!ops.extCfg.EnableIPv4 && !fe.Address.IsIPv6()) {
		return nil
	}

	if err := ops.deleteFrontend(fe); err != nil {
		ops.log.Warn("Deleting frontend failed, retrying", logfields.Error, err)
		return err
	}

	if fe.Type == loadbalancer.SVCTypeNodePort ||
		fe.Type == loadbalancer.SVCTypeHostPort && fe.Address.AddrCluster().IsUnspecified() {

		proto := loadbalancer.L4TypeAsProtocolNumber(fe.Address.Protocol())
		key := nodePortAddrKey{family: fe.Address.IsIPv6(), port: fe.Address.Port(), protocol: proto}
		addrs := ops.nodePortAddrByPort[key]
		for _, addr := range addrs {
			fe = fe.Clone()
			fe.Address = loadbalancer.NewL3n4Addr(
				fe.Address.Protocol(),
				cmtypes.AddrClusterFrom(addr, 0),
				fe.Address.Port(),
				fe.Address.Scope(),
			)
			if err := ops.deleteFrontend(fe); err != nil {
				ops.log.Warn("Deleting frontend failed, retrying", logfields.Error, err)
				return err
			}
		}
		delete(ops.nodePortAddrByPort, key)
	}

	return nil
}

func (ops *BPFOps) deleteRestoredQuarantinedBackends(fe loadbalancer.L3n4Addr, bes ...loadbalancer.L3n4Addr) {
	if ops.restoredQuarantinedBackends == nil {
		return
	}
	if len(bes) == 0 {
		delete(ops.restoredQuarantinedBackends, fe)
	} else {
		backends := ops.restoredQuarantinedBackends[fe]
		if len(backends) > 0 {
			backends.Delete(bes...)
		}
		if len(backends) == 0 {
			delete(ops.restoredQuarantinedBackends, fe)
		}
	}
	if len(ops.restoredQuarantinedBackends) == 0 {
		ops.restoredQuarantinedBackends = nil
	}
}

func (ops *BPFOps) deleteFrontend(fe *loadbalancer.Frontend) error {
	feID, err := ops.serviceIDAlloc.lookupLocalID(fe.Address)
	if err != nil {
		ops.log.Debug("Delete frontend: no ID found", logfields.Address, fe.Address)
		// Since no ID was found we can assume this frontend was never reconciled.
		return nil
	}

	ops.log.Debug("Delete frontend",
		logfields.ID, feID,
		logfields.Address, fe.Address,
	)

	// Drop any restored quarantine state
	ops.deleteRestoredQuarantinedBackends(fe.Address)

	// Delete Maglev.
	if ops.useMaglev(fe) {
		if err := ops.LBMaps.DeleteMaglev(maps.MaglevOuterKey{RevNatID: uint16(feID)}, fe.Address.IsIPv6()); err != nil {
			return fmt.Errorf("ops.LBMaps.DeleteMaglev failed: %w", err)
		}
	}

	if ops.extCfg.EnableSessionAffinity {
		// Clean up any potential affinity match entries. We do this regardless of
		// whether or not SessionAffinity is enabled as it might've been toggled by
		// the user. Could optimize this by holding some more state if needed.
		for addr := range ops.backendReferences[fe.Address] {
			err := ops.deleteAffinityMatch(feID, ops.backendStates[addr].id)
			if err != nil {
				return fmt.Errorf("delete affinity match %d: %w", feID, err)
			}
		}
	}

	for _, orphanState := range ops.orphanBackends(fe.Address, nil) {
		ops.log.Debug("Delete orphan backend", logfields.Address, orphanState.addr)
		if err := ops.deleteBackend(orphanState.addr.IsIPv6(), orphanState.id); err != nil {
			return fmt.Errorf("delete backend %d: %w", orphanState.id, err)
		}
		ops.releaseBackend(orphanState.id, orphanState.addr)
	}

	var svcKey maps.ServiceKey
	var revNatKey maps.RevNatKey

	ip := fe.Address.AddrCluster().AsNetIP()
	proto, err := u8proto.ParseProtocol(fe.Address.Protocol())
	if err != nil {
		return fmt.Errorf("invalid L4 protocol %q: %w", fe.Address.Protocol(), err)
	}
	if fe.Address.IsIPv6() {
		svcKey = maps.NewService6Key(ip, fe.Address.Port(), proto, fe.Address.Scope(), 0)
		revNatKey = maps.NewRevNat6Key(uint16(feID))
	} else {
		svcKey = maps.NewService4Key(ip, fe.Address.Port(), proto, fe.Address.Scope(), 0)
		revNatKey = maps.NewRevNat4Key(feID)
	}

	// Delete all slots including master.
	numBackends := len(ops.backendReferences[fe.Address])
	for i := 0; i <= numBackends; i++ {
		svcKey.SetBackendSlot(i)
		ops.log.Debug("Delete service slot",
			logfields.ID, feID,
			logfields.Address, fe.Address,
			logfields.Slot, i,
		)
		err := ops.LBMaps.DeleteService(svcKey.ToNetwork())
		if err != nil {
			return fmt.Errorf("delete from services map: %w", err)
		}
	}

	err = ops.LBMaps.DeleteRevNat(revNatKey.ToNetwork())
	if err != nil {
		return fmt.Errorf("delete reverse nat %d: %w", feID, err)
	}

	if ops.extCfg.EnableSVCSourceRangeCheck {
		for cidr := range ops.prevSourceRanges[fe.Address] {
			if cidr.Addr().Is6() != fe.Address.IsIPv6() {
				continue
			}
			err := ops.LBMaps.DeleteSourceRange(
				srcRangeKey(cidr, uint16(feID), fe.Address.IsIPv6()),
			)
			if err != nil {
				return fmt.Errorf("update source range: %w", err)
			}
		}
		delete(ops.prevSourceRanges, fe.Address)
	}

	// Decrease the backend reference counts and drop state associated with the frontend.
	ops.updateBackendRefCounts(fe.Address, nil)
	delete(ops.backendReferences, fe.Address)
	ops.serviceIDAlloc.deleteLocalID(feID)

	return nil
}

func (ops *BPFOps) pruneServiceMaps() error {
	toDelete := []maps.ServiceKey{}
	svcCB := func(svcKey maps.ServiceKey, svcValue maps.ServiceValue) {
		svcKey = svcKey.ToHost()
		svcValue = svcValue.ToHost()
		ac, ok := cmtypes.AddrClusterFromIP(svcKey.GetAddress())
		if !ok {
			ops.log.Warn("Prune: bad address in service key", logfields.Key, svcKey)
			return
		}
		proto := loadbalancer.NewL4TypeFromNumber(svcKey.GetProtocol())
		addr := loadbalancer.NewL3n4Addr(
			proto,
			ac,
			svcKey.GetPort(),
			svcKey.GetScope(),
		)
		expectedSlots := 0
		if bes, ok := ops.backendReferences[addr]; ok {
			expectedSlots = 1 + len(bes)
		}
		if svcKey.GetBackendSlot()+1 > expectedSlots {
			ops.log.Debug("pruneServiceMaps: deleting",
				logfields.ID, svcValue.GetRevNat(),
				logfields.Address, addr)
			toDelete = append(toDelete, svcKey.ToNetwork())

			// Drop restored quarantined state
			if svcKey.GetBackendSlot() > 0 {
				if beAddr, found := ops.backendIDAlloc.idToAddr[svcValue.GetBackendID()]; found {
					ops.deleteRestoredQuarantinedBackends(addr, beAddr)
				}
			}
		}
	}
	if err := ops.LBMaps.DumpService(svcCB); err != nil {
		ops.log.Warn("Failed to dump service maps", logfields.Error, err)
	}

	for _, key := range toDelete {
		if err := ops.LBMaps.DeleteService(key); err != nil {
			ops.log.Warn("Failed to delete from service map while pruning", logfields.Error, err)
		}
	}
	return nil
}

func (ops *BPFOps) pruneBackendMaps() error {
	toDelete := []maps.BackendKey{}
	beCB := func(beKey maps.BackendKey, beValue maps.BackendValue) {
		beValue = beValue.ToHost()
		addr := beValueToAddr(beValue)
		if _, ok := ops.backendStates[addr]; !ok {
			ops.log.Debug("pruneBackendMaps: deleting",
				logfields.ID, beKey.GetID(),
				logfields.Address, addr,
			)
			toDelete = append(toDelete, beKey)
		}
	}
	if err := ops.LBMaps.DumpBackend(beCB); err != nil {
		ops.log.Warn("Failed to dump backend maps", logfields.Error, err)
	}

	for _, key := range toDelete {
		if err := ops.LBMaps.DeleteBackend(key); err != nil {
			ops.log.Warn("Failed to delete from backend map", logfields.Error, err)
		}
	}
	return nil
}

func (ops *BPFOps) pruneRestoredIDs() error {
	ops.restoredServiceIDs = nil
	ops.restoredBackendIDs = nil
	return nil
}

func (ops *BPFOps) pruneRevNat() error {
	toDelete := []maps.RevNatKey{}
	cb := func(key maps.RevNatKey, value maps.RevNatValue) {
		key = key.ToHost()
		if _, ok := ops.serviceIDAlloc.idToAddr[key.GetKey()]; !ok {
			ops.log.Debug("pruneRevNat: enqueing for deletion", logfields.ID, key.GetKey())
			toDelete = append(toDelete, key)
		}
	}
	err := ops.LBMaps.DumpRevNat(cb)
	if err != nil {
		return err
	}
	for _, key := range toDelete {
		err := ops.LBMaps.DeleteRevNat(key.ToNetwork())
		if err != nil {
			ops.log.Warn("Failed to delete from reverse nat map", logfields.Error, err)
		}
	}
	return nil
}

func (ops *BPFOps) pruneSourceRanges() error {
	if !ops.extCfg.EnableSVCSourceRangeCheck {
		return nil
	}

	toDelete := []maps.SourceRangeKey{}
	cb := func(key maps.SourceRangeKey, value *maps.SourceRangeValue) {
		key = key.ToHost()

		// A SourceRange is OK if there's a service with this ID and the
		// CIDR is part of the current set.
		addr, ok := ops.serviceIDAlloc.idToAddr[key.GetRevNATID()]
		if ok {
			cidr := key.GetCIDR()
			cidrAddr, _ := netip.AddrFromSlice(cidr.IP)
			ones, _ := cidr.Mask.Size()
			prefix := netip.PrefixFrom(cidrAddr, ones)
			var cidrs sets.Set[netip.Prefix]
			cidrs, ok = ops.prevSourceRanges[addr]
			ok = ok && cidrs.Has(prefix)
		}
		if !ok {
			ops.log.Debug("pruneSourceRanges: enqueing for deletion",
				logfields.ID, key.GetRevNATID(),
				logfields.CIDR, key.GetCIDR())
			toDelete = append(toDelete, key)
		}
	}
	err := ops.LBMaps.DumpSourceRange(cb)
	if err != nil {
		return err
	}
	for _, key := range toDelete {
		err := ops.LBMaps.DeleteSourceRange(key.ToNetwork())
		if err != nil {
			ops.log.Warn("Failed to delete from source range map", logfields.Error, err)
		}
	}
	return nil
}

func (ops *BPFOps) pruneMaglev() error {
	type outerKeyWithIPVersion struct {
		maps.MaglevOuterKey
		ipv6 bool
	}
	toDelete := []outerKeyWithIPVersion{}
	cb := func(key maps.MaglevOuterKey, _ maps.MaglevOuterVal, _ maps.MaglevInnerKey, _ *maps.MaglevInnerVal, ipv6 bool) {
		if _, ok := ops.serviceIDAlloc.idToAddr[loadbalancer.ServiceID(key.RevNatID)]; !ok {
			ops.log.Debug("pruneMaglev: enqueing for deletion", logfields.ID, key.RevNatID)
			toDelete = append(toDelete, outerKeyWithIPVersion{key, ipv6})
		}
	}
	err := ops.LBMaps.DumpMaglev(cb)
	if err != nil {
		return err
	}
	var errs []error
	for _, okwiv := range toDelete {
		err := ops.LBMaps.DeleteMaglev(okwiv.MaglevOuterKey, okwiv.ipv6)
		if err != nil {
			ops.log.Warn("Failed to delete from Maglev map",
				logfields.ID, okwiv.MaglevOuterKey.RevNatID,
				logfields.Error, err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Prune implements reconciler.Operations.
func (ops *BPFOps) Prune(_ context.Context, _ statedb.ReadTxn, _ iter.Seq2[*loadbalancer.Frontend, statedb.Revision]) error {
	ops.mu.Lock()
	defer ops.mu.Unlock()
	defer func() { ops.pruneCount.Add(1) }()
	ops.log.Debug("Pruning")
	return errors.Join(
		ops.pruneRestoredIDs(),
		ops.pruneServiceMaps(),
		ops.pruneBackendMaps(),
		ops.pruneRevNat(),
		ops.pruneSourceRanges(),
		ops.pruneMaglev(),
	)
}

// Update implements reconciler.Operations.
func (ops *BPFOps) Update(_ context.Context, txn statedb.ReadTxn, _ statedb.Revision, fe *loadbalancer.Frontend) error {
	ops.mu.Lock()
	defer ops.mu.Unlock()
	defer ops.setLastUpdatedAt()

	if (!ops.extCfg.EnableIPv6 && fe.Address.IsIPv6()) || (!ops.extCfg.EnableIPv4 && !fe.Address.IsIPv6()) {
		return nil
	}

	if err := ops.updateFrontend(fe); err != nil {
		ops.log.Warn("Updating frontend failed", logfields.Error, err)
		return err
	}

	if fe.Type == loadbalancer.SVCTypeNodePort ||
		fe.Type == loadbalancer.SVCTypeHostPort && fe.Address.AddrCluster().IsUnspecified() {
		// For NodePort create entries for each node address.
		// For HostPort only create them if the address was not specified (HostIP is unset).
		proto := loadbalancer.L4TypeAsProtocolNumber(fe.Address.Protocol())
		key := nodePortAddrKey{family: fe.Address.IsIPv6(), port: fe.Address.Port(), protocol: proto}
		old := sets.New(ops.nodePortAddrByPort[key]...)

		// Collect the node addresses suitable for NodePort that match the IP family of
		// the frontend.
		nodePortAddrs := statedb.Collect(
			statedb.Filter(
				statedb.Map(
					ops.nodeAddrs.List(txn, tables.NodeAddressNodePortIndex.Query(true)),
					func(addr tables.NodeAddress) netip.Addr { return addr.Addr }),
				func(addr netip.Addr) bool {
					return addr.Is6() == fe.Address.IsIPv6()
				},
			),
		)

		// Create the NodePort/HostPort frontends with the node addresses.
		for _, addr := range nodePortAddrs {
			fe = fe.Clone()
			fe.Address = loadbalancer.NewL3n4Addr(
				fe.Address.Protocol(),
				cmtypes.AddrClusterFrom(addr, 0),
				fe.Address.Port(),
				fe.Address.Scope(),
			)
			if err := ops.updateFrontend(fe); err != nil {
				ops.log.Warn("Updating frontend failed",
					logfields.Error, err,
					logfields.Address, fe.Address,
				)
				return err
			}
			old.Delete(addr)
		}

		// Delete orphan NodePort/HostPort frontends
		for addr := range old {
			fe = fe.Clone()
			fe.Address = loadbalancer.NewL3n4Addr(
				fe.Address.Protocol(),
				cmtypes.AddrClusterFrom(addr, 0),
				fe.Address.Port(),
				fe.Address.Scope(),
			)
			if err := ops.deleteFrontend(fe); err != nil {
				ops.log.Warn("Deleting orphan frontend failed",
					logfields.Error, err,
					logfields.Address, fe.Address,
				)
				return err
			}
		}
		ops.nodePortAddrByPort[key] = nodePortAddrs
	}

	return nil
}

func (ops *BPFOps) updateFrontend(fe *loadbalancer.Frontend) error {
	// WARNING: This method must be idempotent. Any updates to state must happen only after
	// the operations that depend on the state have been performed. If this invariant is not
	// followed then we may leak data due to not retrying a failed operation.

	svc := fe.Service
	proxyDelegation := svc.GetProxyDelegation()

	// Check for invalid feature combinations to catch bugs at the upper layers.
	switch {
	case svc.SessionAffinity && svc.ProxyRedirect != nil:
		return fmt.Errorf("invalid feature combination: SessionAffinity with proxy redirection is not supported")
	case svc.LoopbackHostPort && proxyDelegation != loadbalancer.SVCProxyDelegationNone:
		return fmt.Errorf("invalid feature combination: HostPort loopback with proxy delegation is not supported ")
	}

	// Assign/lookup an identifier for the service. May fail if we have run out of IDs.
	// The Frontend.ID field is purely for debugging purposes.
	var feID loadbalancer.ServiceID
	if id, found := ops.restoredServiceIDs[fe.Address]; found {
		feID = id
		ops.serviceIDAlloc.addID(fe.Address, id)
		delete(ops.restoredServiceIDs, fe.Address)
	} else {
		var err error
		feID, err = ops.serviceIDAlloc.acquireLocalID(fe.Address)
		if err != nil {
			return fmt.Errorf("failed to allocate id: %w", err)
		}
	}
	fe.ID = loadbalancer.ServiceID(feID)

	var svcKey maps.ServiceKey
	var svcVal maps.ServiceValue

	proto, err := u8proto.ParseProtocol(fe.Address.Protocol())
	if err != nil {
		return fmt.Errorf("invalid L4 protocol %q: %w", fe.Address.Protocol(), err)
	}

	ip := fe.Address.AddrCluster().AsNetIP()
	if fe.Address.IsIPv6() {
		svcKey = maps.NewService6Key(ip, fe.Address.Port(), proto, fe.Address.Scope(), 0)
		svcVal = &maps.Service6Value{}
	} else {
		svcKey = maps.NewService4Key(ip, fe.Address.Port(), proto, fe.Address.Scope(), 0)
		svcVal = &maps.Service4Value{}
	}

	svcType := fe.Type
	if fe.RedirectTo != nil {
		svcType = loadbalancer.SVCTypeLocalRedirect
	}

	// isRoutable denotes whether this service can be accessed from outside the cluster.
	isRoutable := !svcKey.IsSurrogate() &&
		(svcType != loadbalancer.SVCTypeClusterIP || ops.cfg.ExternalClusterIP)

	forwardingMode := loadbalancer.ToSVCForwardingMode(ops.cfg.LBMode, uint8(proto))
	if ops.cfg.LBModeAnnotation && svc.ForwardingMode != loadbalancer.SVCForwardingModeUndef {
		forwardingMode = svc.ForwardingMode
	}

	flag := loadbalancer.NewSvcFlag(&loadbalancer.SvcFlagParam{
		SvcType:          svcType,
		SvcNatPolicy:     svc.NatPolicy,
		SvcFwdModeDSR:    forwardingMode == loadbalancer.SVCForwardingModeDSR,
		SvcExtLocal:      svc.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal,
		SvcIntLocal:      svc.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal,
		SessionAffinity:  svc.SessionAffinity,
		IsRoutable:       isRoutable,
		SourceRangeDeny:  svc.GetSourceRangesPolicy() == loadbalancer.SVCSourceRangesPolicyDeny,
		CheckSourceRange: len(svc.SourceRanges) > 0,
		L7LoadBalancer:   svc.ProxyRedirect.Redirects(fe.ServicePort),
		LoopbackHostport: svc.LoopbackHostPort || proxyDelegation != loadbalancer.SVCProxyDelegationNone,
		Quarantined:      false,
	})
	svcVal.SetFlags(flag.UInt16())
	svcVal.SetRevNat(int(feID))

	// Gather backends for the service
	orderedBackends := ops.sortedBackends(fe)

	// Clean up any orphan backends to make room for new backends
	backendAddrs := sets.New[loadbalancer.L3n4Addr]()
	for _, be := range orderedBackends {
		backendAddrs.Insert(be.Address)
	}

	for _, orphanState := range ops.orphanBackends(fe.Address, backendAddrs) {
		ops.log.Debug("Delete orphan backend", logfields.Address, orphanState.addr)
		ops.deleteRestoredQuarantinedBackends(fe.Address, orphanState.addr)
		if err := ops.deleteBackend(orphanState.addr.IsIPv6(), orphanState.id); err != nil {
			return fmt.Errorf("delete backend: %w", err)
		}
		if ops.extCfg.EnableSessionAffinity {
			if err := ops.deleteAffinityMatch(feID, orphanState.id); err != nil {
				return fmt.Errorf("delete affinity match: %w", err)
			}
		}
		ops.releaseBackend(orphanState.id, orphanState.addr)
	}

	activeCount, terminatingCount, inactiveCount := 0, 0, 0

	// Update backends that are new or changed.
	slotID := 1
	for i, be := range orderedBackends {
		var beID loadbalancer.BackendID
		if s, ok := ops.backendStates[be.Address]; ok && s.id != 0 {
			beID = s.id
		} else {
			if id, found := ops.restoredBackendIDs[be.Address]; found {
				beID = id
				ops.backendIDAlloc.addID(be.Address, id)
				delete(ops.restoredBackendIDs, be.Address)
			} else {
				var err error
				beID, err = ops.backendIDAlloc.acquireLocalID(be.Address)
				if err != nil {
					return err
				}
			}
		}

		if ops.needsUpdate(be.Address, be.Revision) {
			ops.log.Debug("Update backend",
				logfields.Backend, be.BackendParams,
				logfields.ID, beID,
				logfields.Address, be.Address,
			)
			if err := ops.upsertBackend(beID, be.BackendParams); err != nil {
				return fmt.Errorf("upsert backend: %w", err)
			}

			ops.updateBackendRevision(beID, be.Address, be.Revision)
		}

		if be.State == loadbalancer.BackendStateMaintenance {
			// Backends that are in maintenance are not included in the services map.
			continue
		}

		// Update the service slot for the backend. We do this regardless
		// if the backend entry is up-to-date since the backend slot order might've
		// changed.
		// Since backends are iterated in the order of their state with active first
		// the slot ids here are sequential.
		ops.log.Debug("Update service slot",
			logfields.ID, beID,
			logfields.Slot, slotID,
			logfields.BackendID, beID)

		svcVal.SetBackendID(beID)
		svcVal.SetRevNat(int(feID))
		svcKey.SetBackendSlot(i + 1)
		if err := ops.upsertService(svcKey, svcVal); err != nil {
			return fmt.Errorf("upsert service: %w", err)
		}

		if ops.extCfg.EnableSessionAffinity {
			// TODO: Most likely we'll just need to keep some state on the reconciled SessionAffinity
			// state to avoid the extra syscalls when session affinity is not enabled.
			// For now we update these regardless so that we handle properly the SessionAffinity being
			// flipped on and then off.
			if svc.SessionAffinity && be.State == loadbalancer.BackendStateActive {
				ops.log.Debug("Update affinity",
					logfields.ID, feID,
					logfields.BackendID, beID)
				if err := ops.upsertAffinityMatch(feID, beID); err != nil {
					return fmt.Errorf("upsert affinity match: %w", err)
				}
			} else {
				// SessionAffinity either disabled or backend not active, no matter which
				// clean up any affinity match that might exist.
				if err := ops.deleteAffinityMatch(feID, beID); err != nil {
					return fmt.Errorf("delete affinity match: %w", err)
				}
			}
		}

		if !be.UnhealthyUpdatedAt.IsZero() {
			ops.deleteRestoredQuarantinedBackends(fe.Address, be.Address)
		}

		state := be.State
		if be.Unhealthy {
			// We only care about [be.Unhealthy] for the Count/QCount and not for
			// the state in the backend maps as the backend might be healthy for some
			// service and unhealthy for another.
			state = loadbalancer.BackendStateQuarantined
		}

		switch state {
		case loadbalancer.BackendStateActive:
			activeCount++
		case loadbalancer.BackendStateTerminating:
			terminatingCount++
		default:
			inactiveCount++
		}

		slotID++
	}
	backendCount := slotID - 1

	if activeCount == 0 {
		// If there are no active backends we can use the terminating backends.
		// https://github.com/kubernetes/enhancements/tree/master/keps/sig-network/1669-proxy-terminating-endpoints
		activeCount = terminatingCount
	} else {
		inactiveCount += terminatingCount
	}

	// Update Maglev
	if ops.useMaglev(fe) {
		ops.log.Debug("Update Maglev", logfields.FrontendID, feID)
		if err := ops.updateMaglev(fe, feID, orderedBackends[:activeCount]); err != nil {
			return err
		}
	}

	if ops.extCfg.EnableSVCSourceRangeCheck {
		// Update source ranges. Maintain the invariant that [ops.prevSourceRanges]
		// always reflects what was successfully added to the BPF maps in order
		// not to leak a source range on failed operation.
		prevSourceRanges := ops.prevSourceRanges[fe.Address]
		if prevSourceRanges == nil {
			prevSourceRanges = sets.New[netip.Prefix]()
			ops.prevSourceRanges[fe.Address] = prevSourceRanges
		}
		orphanSourceRanges := prevSourceRanges.Clone()
		srcRangeValue := &maps.SourceRangeValue{}
		for _, prefix := range fe.Service.SourceRanges {
			if prefix.Addr().Is6() != fe.Address.IsIPv6() {
				continue
			}

			err := ops.LBMaps.UpdateSourceRange(
				srcRangeKey(prefix, uint16(feID), fe.Address.IsIPv6()),
				srcRangeValue,
			)
			if err != nil {
				return fmt.Errorf("update source range: %w", err)
			}

			orphanSourceRanges.Delete(prefix)
			prevSourceRanges.Insert(prefix)
		}
		// Remove orphan source ranges.
		for cidr := range orphanSourceRanges {
			if cidr.Addr().Is6() != fe.Address.IsIPv6() {
				continue
			}
			err := ops.LBMaps.DeleteSourceRange(
				srcRangeKey(cidr, uint16(feID), fe.Address.IsIPv6()),
			)
			if err != nil {
				return fmt.Errorf("update source range: %w", err)
			}

			prevSourceRanges.Delete(cidr)
		}
	}

	// Update RevNat
	ops.log.Debug("Update RevNat",
		logfields.ID, feID,
		logfields.Address, fe.Address)
	if err := ops.upsertRevNat(feID, svcKey, svcVal); err != nil {
		return fmt.Errorf("upsert reverse nat: %w", err)
	}

	ops.log.Debug("Update master service",
		logfields.ID, feID,
		logfields.Type, fe.Type,
		logfields.ProxyRedirect, fe.Service.ProxyRedirect,
		logfields.Address, fe.Address,
		logfields.Count, backendCount,
		logfieldActiveCount, activeCount,
		logfieldTerminatingCount, terminatingCount,
		logfieldInactiveCount, inactiveCount)
	if err := ops.upsertMaster(svcKey, svcVal, fe, activeCount, inactiveCount); err != nil {
		return fmt.Errorf("upsert service master: %w", err)
	}

	numPreviousBackends := len(ops.backendReferences[fe.Address])

	if backendCount != numPreviousBackends {
		ops.log.Debug("Cleanup service slots",
			logfields.ID, feID,
			logfields.Count, backendCount,
			logfields.Previous, numPreviousBackends)
		if err := ops.cleanupSlots(svcKey, numPreviousBackends, activeCount+inactiveCount); err != nil {
			return fmt.Errorf("cleanup service slots: %w", err)
		}
	}

	// Finally update the new references. This makes sure any failures reconciling the service slots
	// above can be retried and entries are not leaked.
	ops.updateReferences(fe.Address, backendAddrs)

	return nil
}

func (ops *BPFOps) lbAlgorithm(fe *loadbalancer.Frontend) loadbalancer.SVCLoadBalancingAlgorithm {
	if !ops.cfg.AlgorithmAnnotation {
		// Use the undefined algorithm to fall back to default when annotations are disabled.
		return loadbalancer.SVCLoadBalancingAlgorithmUndef
	}
	return fe.Service.GetLBAlgorithmAnnotation()
}

func (ops *BPFOps) useMaglev(fe *loadbalancer.Frontend) bool {
	alg := ops.lbAlgorithm(fe)
	switch {
	// Wildcarded frontend is not exposed for external traffic.
	case fe.Address.AddrCluster().IsUnspecified():
		return false

	// Maglev algorithm annotation overrides rest of the checks.
	case alg != loadbalancer.SVCLoadBalancingAlgorithmUndef:
		return alg == loadbalancer.SVCLoadBalancingAlgorithmMaglev

	case ops.cfg.LBAlgorithm != loadbalancer.LBAlgorithmMaglev:
		return false

	// Provision the Maglev LUT for ClusterIP only if ExternalClusterIP is
	// enabled because ClusterIP can also be accessed from outside with this
	// setting. We don't do it unconditionally to avoid increasing memory
	// footprint.
	case fe.Type == loadbalancer.SVCTypeClusterIP && !ops.cfg.ExternalClusterIP:
		return false

	default:
		// Only provision the Maglev LUT for service types which are reachable
		// from outside the node.
		switch fe.Type {
		case loadbalancer.SVCTypeClusterIP,
			loadbalancer.SVCTypeNodePort,
			loadbalancer.SVCTypeLoadBalancer,
			loadbalancer.SVCTypeHostPort,
			loadbalancer.SVCTypeExternalIPs:
			return true
		}
		return false
	}
}

func (ops *BPFOps) upsertService(svcKey maps.ServiceKey, svcVal maps.ServiceValue) error {
	var err error
	svcKey = svcKey.ToNetwork()
	svcVal = svcVal.ToNetwork()

	err = ops.LBMaps.UpdateService(svcKey, svcVal)
	if errors.Is(err, unix.E2BIG) {
		return fmt.Errorf("Unable to update service entry %+v => %+v: "+
			"Unable to update element for LB bpf map: "+
			"You can resize it with the flag \"--%s\". "+
			"The resizing might break existing connections to services",
			svcKey, svcVal, loadbalancer.LBMapEntriesName)
	}
	return err
}

func (ops *BPFOps) upsertMaster(svcKey maps.ServiceKey, svcVal maps.ServiceValue, fe *loadbalancer.Frontend, activeBackends, inactiveBackends int) error {
	svcVal.SetCount(activeBackends)
	svcVal.SetQCount(inactiveBackends)
	svcKey.SetBackendSlot(0)
	svcVal.SetBackendID(0)
	svcVal.SetLbAlg(ops.lbAlgorithm(fe))

	svc := fe.Service

	// Set the SessionAffinity/L7ProxyPort. These re-use the "backend ID".
	if svc.SessionAffinity && ops.extCfg.EnableSessionAffinity {
		if err := svcVal.SetSessionAffinityTimeoutSec(uint32(svc.SessionAffinityTimeout.Seconds())); err != nil {
			return err
		}
	}
	if svc.ProxyRedirect.Redirects(fe.ServicePort) {
		svcVal.SetL7LBProxyPort(svc.ProxyRedirect.ProxyPort)
	}
	return ops.upsertService(svcKey, svcVal)
}

func (ops *BPFOps) cleanupSlots(svcKey maps.ServiceKey, oldCount, newCount int) error {
	for i := newCount; i < oldCount; i++ {
		svcKey.SetBackendSlot(i + 1)
		err := ops.LBMaps.DeleteService(svcKey.ToNetwork())
		if err != nil {
			return fmt.Errorf("cleanup service slot %q: %w", svcKey.String(), err)
		}
	}
	return nil
}

func (ops *BPFOps) upsertBackend(id loadbalancer.BackendID, be *loadbalancer.BackendParams) (err error) {
	var lbbe maps.Backend
	proto, err := u8proto.ParseProtocol(be.Address.Protocol())
	if err != nil {
		return fmt.Errorf("invalid L4 protocol %q: %w", be.Address.Protocol(), err)
	}

	if be.Address.AddrCluster().Is6() {
		lbbe, err = maps.NewBackend6V3(id, be.Address.AddrCluster(), be.Address.Port(), proto,
			be.State, ops.extCfg.GetZoneID(be.Zone))
		if err != nil {
			return err
		}
	} else {
		lbbe, err = maps.NewBackend4V3(id, be.Address.AddrCluster(), be.Address.Port(), proto,
			be.State, ops.extCfg.GetZoneID(be.Zone))
		if err != nil {
			return err
		}
	}
	return ops.LBMaps.UpdateBackend(
		lbbe.GetKey(),
		lbbe.GetValue().ToNetwork(),
	)
}

func (ops *BPFOps) deleteBackend(ipv6 bool, id loadbalancer.BackendID) error {
	var key maps.BackendKey
	if ipv6 {
		key = maps.NewBackend6KeyV3(id)
	} else {
		key = maps.NewBackend4KeyV3(id)
	}
	err := ops.LBMaps.DeleteBackend(key)
	if err != nil {
		return fmt.Errorf("delete backend %d: %w", id, err)
	}
	return nil
}

func (ops *BPFOps) upsertAffinityMatch(id loadbalancer.ServiceID, beID loadbalancer.BackendID) error {
	key := &maps.AffinityMatchKey{
		BackendID: beID,
		RevNATID:  uint16(id),
	}
	var value maps.AffinityMatchValue
	return ops.LBMaps.UpdateAffinityMatch(key.ToNetwork(), &value)
}

func (ops *BPFOps) deleteAffinityMatch(id loadbalancer.ServiceID, beID loadbalancer.BackendID) error {
	key := &maps.AffinityMatchKey{
		BackendID: beID,
		RevNATID:  uint16(id),
	}
	return ops.LBMaps.DeleteAffinityMatch(key.ToNetwork())
}

func (ops *BPFOps) upsertRevNat(id loadbalancer.ServiceID, svcKey maps.ServiceKey, svcVal maps.ServiceValue) error {
	zeroValue := svcVal.New().(maps.ServiceValue)
	zeroValue.SetRevNat(int(id))
	revNATKey := zeroValue.RevNatKey()
	revNATValue := svcKey.RevNatValue()

	if revNATKey.GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0)")
	}
	err := ops.LBMaps.UpdateRevNat(revNATKey.ToNetwork(), revNATValue.ToNetwork())
	if err != nil {
		return fmt.Errorf("Unable to update reverse NAT %+v => %+v: %w", revNATKey, revNATValue, err)
	}
	return nil

}

type backendWithRevision struct {
	*loadbalancer.BackendParams
	Revision statedb.Revision
}

func (ops *BPFOps) updateMaglev(fe *loadbalancer.Frontend, feID loadbalancer.ServiceID, activeBackends []backendWithRevision) error {
	if len(activeBackends) == 0 {
		if err := ops.LBMaps.DeleteMaglev(maps.MaglevOuterKey{RevNatID: uint16(feID)}, fe.Address.IsIPv6()); err != nil {
			return fmt.Errorf("ops.LBMaps.DeleteMaglev failed: %w", err)
		}
		return nil
	}
	maglevTable, err := ops.computeMaglevTable(activeBackends)
	if err != nil {
		return fmt.Errorf("ops.computeMaglevTable failed: %w", err)
	}
	if err := ops.LBMaps.UpdateMaglev(maps.MaglevOuterKey{RevNatID: uint16(feID)}, maglevTable, fe.Address.IsIPv6()); err != nil {
		return fmt.Errorf("ops.LBMaps.UpdateMaglev failed: %w", err)
	}
	return nil
}

var _ reconciler.Operations[*loadbalancer.Frontend] = &BPFOps{}

func (ops *BPFOps) updateBackendRefCounts(frontend loadbalancer.L3n4Addr, backends sets.Set[loadbalancer.L3n4Addr]) {
	newRefs := backends.Clone()

	// Decrease reference counts of backends that are no longer referenced
	// by this frontend.
	if oldRefs, ok := ops.backendReferences[frontend]; ok {
		for addr := range oldRefs {
			if newRefs.Has(addr) {
				newRefs.Delete(addr)
				continue
			}
			s, ok := ops.backendStates[addr]
			if ok && s.refCount > 1 {
				s.refCount--
				ops.backendStates[addr] = s
			}
		}
	}

	// Increase the reference counts of backends that are newly
	// referenced.
	for addr := range newRefs {
		s := ops.backendStates[addr]
		s.addr = addr
		s.refCount++
		ops.backendStates[addr] = s
	}
}

func (ops *BPFOps) updateReferences(frontend loadbalancer.L3n4Addr, backends sets.Set[loadbalancer.L3n4Addr]) {
	ops.updateBackendRefCounts(frontend, backends)
	ops.backendReferences[frontend] = backends
}

func (ops *BPFOps) orphanBackends(frontend loadbalancer.L3n4Addr, backends sets.Set[loadbalancer.L3n4Addr]) (orphans []backendState) {
	if oldRefs, ok := ops.backendReferences[frontend]; ok {
		for addr := range oldRefs {
			if backends.Has(addr) {
				continue
			}
			// If there is only one reference to this backend then it's from this frontend and
			// since it's not part of the new set it has become an orphan.
			if state, ok := ops.backendStates[addr]; ok && state.refCount <= 1 {
				orphans = append(orphans, state)
			}
		}
	}
	return orphans
}

// checkBackend returns true if the backend should be updated.
func (ops *BPFOps) needsUpdate(addr loadbalancer.L3n4Addr, rev statedb.Revision) bool {
	return rev > ops.backendStates[addr].revision
}

func (ops *BPFOps) updateBackendRevision(id loadbalancer.BackendID, addr loadbalancer.L3n4Addr, rev statedb.Revision) {
	s := ops.backendStates[addr]
	s.id = id
	s.revision = rev
	ops.backendStates[addr] = s
}

// releaseBackend releases the backends information and the ID when it has been deleted
// successfully.
func (ops *BPFOps) releaseBackend(id loadbalancer.BackendID, addr loadbalancer.L3n4Addr) {
	delete(ops.backendStates, addr)
	ops.backendIDAlloc.deleteLocalID(id)
}

func (ops *BPFOps) computeMaglevTable(bes []backendWithRevision) ([]loadbalancer.BackendID, error) {
	var errs []error
	backendInfos := func(yield func(maglev.BackendInfo) bool) {
		for _, be := range bes {
			id, err := ops.backendIDAlloc.lookupLocalID(be.Address)
			if err != nil {
				errs = append(errs, fmt.Errorf("local id for address %s not found: %w", be.Address.String(), err))
				continue
			}
			if !yield(maglev.BackendInfo{
				ID:     loadbalancer.BackendID(id),
				Addr:   be.Address,
				Weight: be.Weight,
			}) {
				break
			}
		}
	}
	return ops.maglev.GetLookupTable(backendInfos), errors.Join(errs...)
}

// sortedBackends sorts the backends in-place with the following sort order:
// - State (active first)
// - Address
// - Port
//
// Backends are sorted to deterministically to keep the order stable in BPF maps
// when updating.
func (ops *BPFOps) sortedBackends(fe *loadbalancer.Frontend) []backendWithRevision {
	quarantined := ops.restoredQuarantinedBackends[fe.Address]

	bes := []backendWithRevision{}
	for be, rev := range fe.Backends {
		if be.UnhealthyUpdatedAt.IsZero() && quarantined.Has(be.Address) {
			be.Unhealthy = true
		}
		bes = append(bes, backendWithRevision{&be, rev})
	}
	sort.Slice(bes, func(i, j int) bool {
		a, b := bes[i], bes[j]
		switch {
		case !a.Unhealthy && b.Unhealthy:
			return true
		case a.Unhealthy && !b.Unhealthy:
			return false
		case a.State < b.State:
			return true
		case a.State > b.State:
			return false
		default:
			switch a.Address.AddrCluster().Compare(b.Address.AddrCluster()) {
			case -1:
				return true
			case 0:
				return a.Address.Port() < b.Address.Port()
			default:
				return false
			}
		}
	})
	return bes
}

func (ops *BPFOps) StateIsEmpty() bool {
	return len(ops.backendReferences) == 0 &&
		len(ops.backendStates) == 0 &&
		len(ops.nodePortAddrByPort) == 0 &&
		len(ops.serviceIDAlloc.addrToId) == 0 &&
		len(ops.backendIDAlloc.addrToId) == 0
}

// StateSummary returns a multi-line summary of the internal state.
// Used in tests.
func (ops *BPFOps) StateSummary() string {
	var b strings.Builder

	fmt.Fprintf(&b, "serviceIDs: %d\n", len(ops.serviceIDAlloc.idToAddr))
	fmt.Fprintf(&b, "restoredServiceIDs: %d\n", len(ops.restoredServiceIDs))
	fmt.Fprintf(&b, "backendIDs: %d\n", len(ops.backendIDAlloc.idToAddr))
	fmt.Fprintf(&b, "restoredBackendIDs: %d\n", len(ops.restoredBackendIDs))
	fmt.Fprintf(&b, "backendStates: %d\n", len(ops.backendStates))
	fmt.Fprintf(&b, "backendReferences: %d\n", len(ops.backendReferences))
	fmt.Fprintf(&b, "nodePortAddrByPort: %d\n", len(ops.nodePortAddrByPort))
	fmt.Fprintf(&b, "prevSourceRanges: %d\n", len(ops.prevSourceRanges))
	fmt.Fprintf(&b, "restoredQuarantines: %d\n", len(ops.restoredQuarantinedBackends))
	return b.String()
}

func srcRangeKey(cidr netip.Prefix, revNATID uint16, ipv6 bool) maps.SourceRangeKey {
	const (
		lpmPrefixLen4 = 16 + 16 // sizeof(SourceRangeKey4.RevNATID)+sizeof(SourceRangeKey4.Pad)
		lpmPrefixLen6 = 16 + 16 // sizeof(SourceRangeKey6.RevNATID)+sizeof(SourceRangeKey6.Pad)
	)
	ones := cidr.Bits()
	id := byteorder.HostToNetwork16(revNATID)
	if ipv6 {
		key := &maps.SourceRangeKey6{PrefixLen: uint32(ones) + lpmPrefixLen6, RevNATID: id}
		as16 := cidr.Addr().As16()
		copy(key.Address[:], as16[:])
		return key
	} else {
		key := &maps.SourceRangeKey4{PrefixLen: uint32(ones) + lpmPrefixLen4, RevNATID: id}
		as4 := cidr.Addr().As4()
		copy(key.Address[:], as4[:])
		return key
	}
}
