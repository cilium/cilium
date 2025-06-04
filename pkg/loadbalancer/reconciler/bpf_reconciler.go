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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	// initGracePeriod is the amount of time we wait for the load-balancing tables to be initialized before
	// we start reconciling towards the BPF maps. This reduces the probability that load-balancing is scaled
	// down temporarily due to not yet seeing all backends.
	//
	// We must not wait forever for initialization though due to potential interdependencies between load-balancing
	// data sources. For example we might depend on Kubernetes data to connect to the ClusterMesh api-server and
	// thus may need to first reconcile the Kubernetes services to connect to ClusterMesh (if endpoints have changed
	// while agent was down).
	initGracePeriod = 10 * time.Second
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
			// We give a short grace period for initializers to finish populating the initial contents
			// of the tables to avoid scaling down load-balancing due to e.g. seeing services before
			// the endpoint slices.
			health.OK("Waiting for load-balancing tables to initialize")
			_, initWatch := w.Frontends().Initialized(p.DB.ReadTxn())
			select {
			case <-ctx.Done():
				return nil
			case <-initWatch:
			case <-time.After(initGracePeriod):
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
	LBMaps maps.LBMaps
	log    *slog.Logger
	cfg    loadbalancer.Config
	extCfg loadbalancer.ExternalConfig
	maglev *maglev.Maglev

	serviceIDAlloc     idAllocator
	restoredServiceIDs sets.Set[loadbalancer.ID]
	backendIDAlloc     idAllocator
	restoredBackendIDs sets.Set[loadbalancer.BackendID]

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

	db        *statedb.DB
	nodeAddrs statedb.Table[tables.NodeAddress]
}

type nodePortAddrKey struct {
	family loadbalancer.IPFamily
	port   uint16
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

func newBPFOps(p bpfOpsParams) *BPFOps {
	if !p.Config.EnableExperimentalLB {
		return nil
	}
	ops := &BPFOps{
		cfg:       p.Config,
		extCfg:    p.ExternalConfig,
		maglev:    p.Maglev,
		log:       p.Log,
		LBMaps:    p.LBMaps,
		db:        p.DB,
		nodeAddrs: p.NodeAddresses,
	}
	p.Lifecycle.Append(cell.Hook{OnStart: ops.start})
	return ops
}

func (ops *BPFOps) start(cell.HookContext) (err error) {
	return ops.ResetAndRestore()
}

func (ops *BPFOps) ResetAndRestore() (err error) {
	ops.serviceIDAlloc = newIDAllocator(firstFreeServiceID, maxSetOfServiceID)
	ops.restoredServiceIDs = sets.New[loadbalancer.ID]()
	ops.backendIDAlloc = newIDAllocator(firstFreeBackendID, maxSetOfBackendID)
	ops.restoredBackendIDs = sets.New[loadbalancer.BackendID]()
	ops.backendStates = map[loadbalancer.L3n4Addr]backendState{}
	ops.backendReferences = map[loadbalancer.L3n4Addr]sets.Set[loadbalancer.L3n4Addr]{}
	ops.nodePortAddrByPort = map[nodePortAddrKey][]netip.Addr{}
	ops.prevSourceRanges = map[loadbalancer.L3n4Addr]sets.Set[netip.Prefix]{}

	// Restore backend IDs
	err = ops.LBMaps.DumpBackend(func(key lbmap.BackendKey, value lbmap.BackendValue) {
		value = value.ToHost()
		ops.backendIDAlloc.addID(beValueToAddr(value), loadbalancer.ID(key.GetID()))
		ops.restoredBackendIDs.Insert(key.GetID())
	})
	if err != nil {
		return fmt.Errorf("restore backend ids: %w", err)
	}

	// Gather all services key'd by address.
	serviceSlots := map[loadbalancer.L3n4Addr][]lbmap.ServiceValue{}
	err = ops.LBMaps.DumpService(func(key lbmap.ServiceKey, value lbmap.ServiceValue) {
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

		id := loadbalancer.ID(master.GetRevNat())
		ops.serviceIDAlloc.addID(addr, id)
		ops.restoredServiceIDs.Insert(id)

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
				if addr := ops.backendIDAlloc.entitiesID[loadbalancer.ID(slot.GetBackendID())]; addr != nil {
					backends.Insert(addr.L3n4Addr)
				}
			}
		}
	}
	return nil
}

func svcKeyToAddr(svcKey lbmap.ServiceKey) loadbalancer.L3n4Addr {
	feIP := svcKey.GetAddress()
	feAddrCluster := cmtypes.MustAddrClusterFromIP(feIP)
	proto := loadbalancer.NewL4TypeFromNumber(svcKey.GetProtocol())
	feL3n4Addr := loadbalancer.NewL3n4Addr(proto, feAddrCluster, svcKey.GetPort(), svcKey.GetScope())
	return *feL3n4Addr
}

func beValueToAddr(beValue lbmap.BackendValue) loadbalancer.L3n4Addr {
	beIP := beValue.GetAddress()
	beAddrCluster := cmtypes.MustAddrClusterFromIP(beIP)
	proto := loadbalancer.NewL4TypeFromNumber(beValue.GetProtocol())
	beL3n4Addr := loadbalancer.NewL3n4Addr(proto, beAddrCluster, beValue.GetPort(), 0)
	return *beL3n4Addr
}

// Delete implements reconciler.Operations.
func (ops *BPFOps) Delete(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, fe *loadbalancer.Frontend) error {
	if (!ops.extCfg.EnableIPv6 && fe.Address.IsIPv6()) || (!ops.extCfg.EnableIPv4 && !fe.Address.IsIPv6()) {
		return nil
	}

	if err := ops.deleteFrontend(fe); err != nil {
		ops.log.Warn("Deleting frontend failed, retrying", logfields.Error, err)
		return err
	}

	if fe.Type == loadbalancer.SVCTypeNodePort ||
		fe.Type == loadbalancer.SVCTypeHostPort && fe.Address.AddrCluster.IsUnspecified() {

		key := nodePortAddrKey{family: fe.Address.IsIPv6(), port: fe.Address.Port}
		addrs, ok := ops.nodePortAddrByPort[key]
		if ok {
			for _, addr := range addrs {
				fe = fe.Clone()
				fe.Address.AddrCluster = cmtypes.AddrClusterFrom(addr, 0)
				if err := ops.deleteFrontend(fe); err != nil {
					ops.log.Warn("Deleting frontend failed, retrying", logfields.Error, err)
					return err
				}
			}
			delete(ops.nodePortAddrByPort, key)
		} else {
			ops.log.Warn("no nodePortAddrs", logfields.Port, fe.Address.Port)
		}
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
		if err := ops.LBMaps.DeleteMaglev(lbmap.MaglevOuterKey{RevNatID: uint16(feID)}, fe.Address.IsIPv6()); err != nil {
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

	var svcKey lbmap.ServiceKey
	var revNatKey lbmap.RevNatKey

	ip := fe.Address.AddrCluster.AsNetIP()
	proto, err := u8proto.ParseProtocol(fe.Address.Protocol)
	if err != nil {
		return fmt.Errorf("invalid L4 protocol %q: %w", fe.Address.Protocol, err)
	}
	if fe.Address.IsIPv6() {
		svcKey = lbmap.NewService6Key(ip, fe.Address.Port, proto, fe.Address.Scope, 0)
		revNatKey = lbmap.NewRevNat6Key(uint16(feID))
	} else {
		svcKey = lbmap.NewService4Key(ip, fe.Address.Port, proto, fe.Address.Scope, 0)
		revNatKey = lbmap.NewRevNat4Key(uint16(feID))
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
	toDelete := []lbmap.ServiceKey{}
	svcCB := func(svcKey lbmap.ServiceKey, svcValue lbmap.ServiceValue) {
		svcKey = svcKey.ToHost()
		svcValue = svcValue.ToHost()
		ac, ok := cmtypes.AddrClusterFromIP(svcKey.GetAddress())
		if !ok {
			ops.log.Warn("Prune: bad address in service key", logfields.Key, svcKey)
			return
		}
		proto := loadbalancer.NewL4TypeFromNumber(svcKey.GetProtocol())
		addr := loadbalancer.L3n4Addr{
			AddrCluster: ac,
			L4Addr:      loadbalancer.L4Addr{Protocol: proto, Port: svcKey.GetPort()},
			Scope:       svcKey.GetScope(),
		}
		expectedSlots := 0
		if bes, ok := ops.backendReferences[addr]; ok {
			expectedSlots = 1 + len(bes)
		}
		if svcKey.GetBackendSlot()+1 > expectedSlots {
			ops.log.Info("pruneServiceMaps: deleting",
				logfields.ID, svcValue.GetRevNat(),
				logfields.Address, addr)
			toDelete = append(toDelete, svcKey.ToNetwork())

			// Drop restored quarantined state
			if svcKey.GetBackendSlot() > 0 {
				if beAddr, found := ops.backendIDAlloc.entitiesID[loadbalancer.ID(svcValue.GetBackendID())]; found {
					ops.deleteRestoredQuarantinedBackends(addr, beAddr.L3n4Addr)
				}
			}
		}
	}
	if err := ops.LBMaps.DumpService(svcCB); err != nil {
		ops.log.Warn("Failed to prune service maps", logfields.Error, err)
	}

	for _, key := range toDelete {
		if err := ops.LBMaps.DeleteService(key); err != nil {
			ops.log.Warn("Failed to delete from service map while pruning", logfields.Error, err)
		}
	}
	return nil
}

func (ops *BPFOps) pruneBackendMaps() error {
	toDelete := []lbmap.BackendKey{}
	beCB := func(beKey lbmap.BackendKey, beValue lbmap.BackendValue) {
		beValue = beValue.ToHost()
		addr := beValueToAddr(beValue)
		if _, ok := ops.backendStates[addr]; !ok {
			ops.log.Info("pruneBackendMaps: deleting",
				logfields.ID, beKey.GetID(),
				logfields.Address, addr,
			)
			toDelete = append(toDelete, beKey)
		}
	}
	if err := ops.LBMaps.DumpBackend(beCB); err != nil {
		ops.log.Warn("Failed to prune backend maps", logfields.Error, err)
	}

	for _, key := range toDelete {
		if err := ops.LBMaps.DeleteBackend(key); err != nil {
			ops.log.Warn("Failed to delete from backend map", logfields.Error, err)
		}
	}
	return nil
}

func (ops *BPFOps) pruneRestoredIDs() error {
	for id := range ops.restoredServiceIDs {
		if addr := ops.serviceIDAlloc.entitiesID[id]; addr != nil {
			if _, found := ops.backendReferences[addr.L3n4Addr]; !found {
				// This ID was restored but no frontend appeared to claim it. Free it.
				ops.serviceIDAlloc.deleteLocalID(id)
			}
		}
	}
	for id := range ops.restoredBackendIDs {
		if addr := ops.backendIDAlloc.entitiesID[loadbalancer.ID(id)]; addr != nil {
			if _, found := ops.backendStates[addr.L3n4Addr]; !found {
				// This ID was restored but no frontend appeared to claim it. Free it.
				ops.backendIDAlloc.deleteLocalID(loadbalancer.ID(id))
			}
		}
	}

	ops.restoredServiceIDs = nil
	ops.restoredBackendIDs = nil

	return nil
}

func (ops *BPFOps) pruneRevNat() error {
	toDelete := []lbmap.RevNatKey{}
	cb := func(key lbmap.RevNatKey, value lbmap.RevNatValue) {
		key = key.ToHost()
		if _, ok := ops.serviceIDAlloc.entitiesID[loadbalancer.ID(key.GetKey())]; !ok {
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

	toDelete := []lbmap.SourceRangeKey{}
	cb := func(key lbmap.SourceRangeKey, value *lbmap.SourceRangeValue) {
		key = key.ToHost()

		// A SourceRange is OK if there's a service with this ID and the
		// CIDR is part of the current set.
		addr, ok := ops.serviceIDAlloc.entitiesID[loadbalancer.ID(key.GetRevNATID())]
		if ok {
			cidr := key.GetCIDR()
			cidrAddr, _ := netip.AddrFromSlice(cidr.IP)
			ones, _ := cidr.Mask.Size()
			prefix := netip.PrefixFrom(cidrAddr, ones)
			var cidrs sets.Set[netip.Prefix]
			cidrs, ok = ops.prevSourceRanges[addr.L3n4Addr]
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
		lbmap.MaglevOuterKey
		ipv6 bool
	}
	toDelete := []outerKeyWithIPVersion{}
	cb := func(key lbmap.MaglevOuterKey, _ lbmap.MaglevOuterVal, _ lbmap.MaglevInnerKey, _ *lbmap.MaglevInnerVal, ipv6 bool) {
		if _, ok := ops.serviceIDAlloc.entitiesID[loadbalancer.ID(key.RevNatID)]; !ok {
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
	if (!ops.extCfg.EnableIPv6 && fe.Address.IsIPv6()) || (!ops.extCfg.EnableIPv4 && !fe.Address.IsIPv6()) {
		return nil
	}

	if err := ops.updateFrontend(fe); err != nil {
		ops.log.Warn("Updating frontend failed, retrying", logfields.Error, err)
		return err
	}

	if fe.Type == loadbalancer.SVCTypeNodePort ||
		fe.Type == loadbalancer.SVCTypeHostPort && fe.Address.AddrCluster.IsUnspecified() {
		// For NodePort create entries for each node address.
		// For HostPort only create them if the address was not specified (HostIP is unset).
		key := nodePortAddrKey{family: fe.Address.IsIPv6(), port: fe.Address.Port}
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
			fe.Address.AddrCluster = cmtypes.AddrClusterFrom(addr, 0)
			if err := ops.updateFrontend(fe); err != nil {
				ops.log.Warn("Updating frontend failed, retrying", logfields.Error, err)
				return err
			}
			old.Delete(addr)
		}

		// Delete orphan NodePort/HostPort frontends
		for addr := range old {
			fe = fe.Clone()
			fe.Address.AddrCluster = cmtypes.AddrClusterFrom(addr, 0)
			if err := ops.deleteFrontend(fe); err != nil {
				ops.log.Warn("Deleting orphan frontend failed, retrying", logfields.Error, err)
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
	feID, err := ops.serviceIDAlloc.acquireLocalID(fe.Address, 0)
	if err != nil {
		return fmt.Errorf("failed to allocate id: %w", err)
	}
	fe.ID = loadbalancer.ServiceID(feID)

	var svcKey lbmap.ServiceKey
	var svcVal lbmap.ServiceValue

	proto, err := u8proto.ParseProtocol(fe.Address.Protocol)
	if err != nil {
		return fmt.Errorf("invalid L4 protocol %q: %w", fe.Address.Protocol, err)
	}

	ip := fe.Address.AddrCluster.AsNetIP()
	if fe.Address.IsIPv6() {
		svcKey = lbmap.NewService6Key(ip, fe.Address.Port, proto, fe.Address.Scope, 0)
		svcVal = &lbmap.Service6Value{}
	} else {
		svcKey = lbmap.NewService4Key(ip, fe.Address.Port, proto, fe.Address.Scope, 0)
		svcVal = &lbmap.Service4Value{}
	}

	svcType := fe.Type
	if fe.RedirectTo != nil {
		svcType = loadbalancer.SVCTypeLocalRedirect
	}

	// isRoutable denotes whether this service can be accessed from outside the cluster.
	isRoutable := !svcKey.IsSurrogate() &&
		(svcType != loadbalancer.SVCTypeClusterIP || ops.cfg.ExternalClusterIP)

	forwardingMode := loadbalancer.ToSVCForwardingMode(ops.cfg.LBMode)
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
	backendCount := len(orderedBackends)

	// Update backends that are new or changed.
	for i, be := range orderedBackends {
		var beID loadbalancer.BackendID
		if s, ok := ops.backendStates[be.Address]; ok && s.id != 0 {
			beID = s.id
		} else {
			acquiredID, err := ops.backendIDAlloc.acquireLocalID(be.Address, 0)
			if err != nil {
				return err
			}
			beID = loadbalancer.BackendID(acquiredID)
		}

		if ops.needsUpdate(be.Address, be.Revision) {
			ops.log.Debug("Update backend",
				logfields.Backend, be,
				logfields.ID, beID,
				logfields.Address, be.Address,
			)
			if err := ops.upsertBackend(beID, be.BackendParams); err != nil {
				return fmt.Errorf("upsert backend: %w", err)
			}

			ops.updateBackendRevision(beID, be.Address, be.Revision)
		}

		// Update the service slot for the backend. We do this regardless
		// if the backend entry is up-to-date since the backend slot order might've
		// changed.
		// Since backends are iterated in the order of their state with active first
		// the slot ids here are sequential.
		ops.log.Debug("Update service slot",
			logfields.ID, beID,
			logfields.Slot, i+1,
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
	}

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
		srcRangeValue := &lbmap.SourceRangeValue{}
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
		logfields.Count, backendCount)
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
	case fe.Address.AddrCluster.IsUnspecified():
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

func (ops *BPFOps) upsertService(svcKey lbmap.ServiceKey, svcVal lbmap.ServiceValue) error {
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

func (ops *BPFOps) upsertMaster(svcKey lbmap.ServiceKey, svcVal lbmap.ServiceValue, fe *loadbalancer.Frontend, activeBackends, inactiveBackends int) error {
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

func (ops *BPFOps) cleanupSlots(svcKey lbmap.ServiceKey, oldCount, newCount int) error {
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
	var lbbe lbmap.Backend
	proto, err := u8proto.ParseProtocol(be.Address.Protocol)
	if err != nil {
		return fmt.Errorf("invalid L4 protocol %q: %w", be.Address.Protocol, err)
	}

	if be.Address.AddrCluster.Is6() {
		lbbe, err = lbmap.NewBackend6V3(id, be.Address.AddrCluster, be.Address.Port, proto,
			be.State, ops.extCfg.GetZoneID(be.Zone))
		if err != nil {
			return err
		}
	} else {
		lbbe, err = lbmap.NewBackend4V3(id, be.Address.AddrCluster, be.Address.Port, proto,
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
	var key lbmap.BackendKey
	if ipv6 {
		key = lbmap.NewBackend6KeyV3(id)
	} else {
		key = lbmap.NewBackend4KeyV3(id)
	}
	err := ops.LBMaps.DeleteBackend(key)
	if err != nil {
		return fmt.Errorf("delete backend %d: %w", id, err)
	}
	return nil
}

func (ops *BPFOps) upsertAffinityMatch(id loadbalancer.ID, beID loadbalancer.BackendID) error {
	key := &lbmap.AffinityMatchKey{
		BackendID: beID,
		RevNATID:  uint16(id),
	}
	var value lbmap.AffinityMatchValue
	return ops.LBMaps.UpdateAffinityMatch(key.ToNetwork(), &value)
}

func (ops *BPFOps) deleteAffinityMatch(id loadbalancer.ID, beID loadbalancer.BackendID) error {
	key := &lbmap.AffinityMatchKey{
		BackendID: beID,
		RevNATID:  uint16(id),
	}
	return ops.LBMaps.DeleteAffinityMatch(key.ToNetwork())
}

func (ops *BPFOps) upsertRevNat(id loadbalancer.ID, svcKey lbmap.ServiceKey, svcVal lbmap.ServiceValue) error {
	zeroValue := svcVal.New().(lbmap.ServiceValue)
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

func (ops *BPFOps) updateMaglev(fe *loadbalancer.Frontend, feID loadbalancer.ID, activeBackends []backendWithRevision) error {
	if len(activeBackends) == 0 {
		if err := ops.LBMaps.DeleteMaglev(lbmap.MaglevOuterKey{RevNatID: uint16(feID)}, fe.Address.IsIPv6()); err != nil {
			return fmt.Errorf("ops.LBMaps.DeleteMaglev failed: %w", err)
		}
		return nil
	}
	maglevTable, err := ops.computeMaglevTable(activeBackends)
	if err != nil {
		return fmt.Errorf("ops.computeMaglevTable failed: %w", err)
	}
	if err := ops.LBMaps.UpdateMaglev(lbmap.MaglevOuterKey{RevNatID: uint16(feID)}, maglevTable, fe.Address.IsIPv6()); err != nil {
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
	ops.backendIDAlloc.deleteLocalID(loadbalancer.ID(id))
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
			switch a.Address.AddrCluster.Addr().Compare(b.Address.AddrCluster.Addr()) {
			case -1:
				return true
			case 0:
				return a.Address.Port < b.Address.Port
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
		len(ops.serviceIDAlloc.entities) == 0 &&
		len(ops.backendIDAlloc.entities) == 0
}

// StateSummary returns a multi-line summary of the internal state.
// Used in tests.
func (ops *BPFOps) StateSummary() string {
	var b strings.Builder

	fmt.Fprintf(&b, "serviceIDs: %d\n", len(ops.serviceIDAlloc.entities))
	fmt.Fprintf(&b, "restoredServiceIDs: %d\n", len(ops.restoredServiceIDs))
	fmt.Fprintf(&b, "backendIDs: %d\n", len(ops.backendIDAlloc.entities))
	fmt.Fprintf(&b, "restoredBackendIDs: %d\n", len(ops.restoredBackendIDs))
	fmt.Fprintf(&b, "backendStates: %d\n", len(ops.backendStates))
	fmt.Fprintf(&b, "backendReferences: %d\n", len(ops.backendReferences))
	fmt.Fprintf(&b, "nodePortAddrByPort: %d\n", len(ops.nodePortAddrByPort))
	fmt.Fprintf(&b, "prevSourceRanges: %d\n", len(ops.prevSourceRanges))
	fmt.Fprintf(&b, "restoredQuarantines: %d\n", len(ops.restoredQuarantinedBackends))
	return b.String()
}

// idAllocator contains an internal state of the ID allocator.
type idAllocator struct {
	// entitiesID is a map of all entities indexed by service or backend ID
	entitiesID map[loadbalancer.ID]*loadbalancer.L3n4AddrID

	// entities is a map of all entities indexed by L3n4Addr.StringID()
	entities map[string]loadbalancer.ID

	// nextID is the next ID to attempt to allocate
	nextID loadbalancer.ID

	// maxID is the maximum ID available for allocation
	maxID loadbalancer.ID

	// initNextID is the initial nextID
	initNextID loadbalancer.ID

	// initMaxID is the initial maxID
	initMaxID loadbalancer.ID
}

const (
	// firstFreeServiceID is the first ID for which the services should be assigned.
	firstFreeServiceID = loadbalancer.ID(1)

	// maxSetOfServiceID is maximum number of set of service IDs that can be stored
	// in the kvstore or the local ID allocator.
	maxSetOfServiceID = loadbalancer.ID(0xFFFF)

	// firstFreeBackendID is the first ID for which the backend should be assigned.
	// BPF datapath assumes that backend_id cannot be 0.
	firstFreeBackendID = loadbalancer.ID(1)

	// maxSetOfBackendID is maximum number of set of backendIDs IDs that can be
	// stored in the local ID allocator.
	maxSetOfBackendID = loadbalancer.ID(0xFFFFFFFF)
)

func newIDAllocator(nextID loadbalancer.ID, maxID loadbalancer.ID) idAllocator {
	return idAllocator{
		entitiesID: map[loadbalancer.ID]*loadbalancer.L3n4AddrID{},
		entities:   map[string]loadbalancer.ID{},
		nextID:     nextID,
		maxID:      maxID,
		initNextID: nextID,
		initMaxID:  maxID,
	}
}

func (alloc *idAllocator) addID(svc loadbalancer.L3n4Addr, id loadbalancer.ID) loadbalancer.ID {
	svcID := newID(svc, id)
	alloc.entitiesID[id] = svcID
	alloc.entities[svc.StringID()] = id
	return id
}

func (alloc *idAllocator) acquireLocalID(svc loadbalancer.L3n4Addr, desiredID loadbalancer.ID) (loadbalancer.ID, error) {
	if svcID, ok := alloc.entities[svc.StringID()]; ok {
		if svc, ok := alloc.entitiesID[svcID]; ok {
			return svc.ID, nil
		}
	}

	if desiredID != 0 {
		foundSVC, ok := alloc.entitiesID[desiredID]
		if !ok {
			if desiredID >= alloc.nextID {
				// We don't set nextID to desiredID+1 here, as we don't want to
				// duplicate the logic which deals with the rollover. Next
				// invocation of acquireLocalID(..., 0) will fix the nextID.
				alloc.nextID = desiredID
			}
			return alloc.addID(svc, desiredID), nil
		}
		return 0, fmt.Errorf("Service ID %d is already registered to %q",
			desiredID, foundSVC)
	}

	startingID := alloc.nextID
	rollover := false
	for {
		if alloc.nextID == startingID && rollover {
			break
		} else if alloc.nextID == alloc.maxID {
			alloc.nextID = alloc.initNextID
			rollover = true
		}

		if _, ok := alloc.entitiesID[alloc.nextID]; !ok {
			svcID := alloc.addID(svc, alloc.nextID)
			alloc.nextID++
			return svcID, nil
		}

		alloc.nextID++
	}

	return 0, fmt.Errorf("no service ID available")
}

func (alloc *idAllocator) deleteLocalID(id loadbalancer.ID) {
	if svc, ok := alloc.entitiesID[id]; ok {
		delete(alloc.entitiesID, id)
		delete(alloc.entities, svc.StringID())
	}
}

func (alloc *idAllocator) lookupLocalID(svc loadbalancer.L3n4Addr) (loadbalancer.ID, error) {
	if svcID, ok := alloc.entities[svc.StringID()]; ok {
		return svcID, nil
	}

	return 0, fmt.Errorf("ID not found")
}

func newID(svc loadbalancer.L3n4Addr, id loadbalancer.ID) *loadbalancer.L3n4AddrID {
	return &loadbalancer.L3n4AddrID{
		L3n4Addr: svc,
		ID:       loadbalancer.ID(id),
	}
}

func srcRangeKey(cidr netip.Prefix, revNATID uint16, ipv6 bool) lbmap.SourceRangeKey {
	const (
		lpmPrefixLen4 = 16 + 16 // sizeof(SourceRangeKey4.RevNATID)+sizeof(SourceRangeKey4.Pad)
		lpmPrefixLen6 = 16 + 16 // sizeof(SourceRangeKey6.RevNATID)+sizeof(SourceRangeKey6.Pad)
	)
	ones := cidr.Bits()
	id := byteorder.HostToNetwork16(revNATID)
	if ipv6 {
		key := &lbmap.SourceRangeKey6{PrefixLen: uint32(ones) + lpmPrefixLen6, RevNATID: id}
		as16 := cidr.Addr().As16()
		copy(key.Address[:], as16[:])
		return key
	} else {
		key := &lbmap.SourceRangeKey4{PrefixLen: uint32(ones) + lpmPrefixLen4, RevNATID: id}
		as4 := cidr.Addr().As4()
		copy(key.Address[:], as4[:])
		return key
	}
}
