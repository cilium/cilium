package tables

import (
	"context"
	"sort"
	"time"

	"golang.org/x/exp/maps"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

func serviceReconcilerConfig(bes statedb.RWTable[*Backend]) reconciler.Config[*Service] {
	ops := newServiceOps(bes)
	return reconciler.Config[*Service]{
		FullReconcilationInterval: time.Minute,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   time.Minute,
		IncrementalRoundSize:      500,
		GetObjectStatus:           (*Service).GetBPFStatus,
		WithObjectStatus:          (*Service).WithBPFStatus,
		RateLimiter:               rate.NewLimiter(10*time.Millisecond, 20),
		Operations:                ops,
		BatchOperations:           nil,
	}
}

// backendsState tracks what backends exist and how they're referenced by services.
type backendsState struct {
	allocator *IDAllocator

	revisions map[loadbalancer.L3n4Addr]statedb.Revision

	// references maps service frontend to the associated backends
	references map[loadbalancer.L3n4Addr]sets.Set[loadbalancer.L3n4Addr]
	refCounts  map[loadbalancer.L3n4Addr]int
}

func (s *backendsState) updateReferences(frontend loadbalancer.L3n4Addr, backends sets.Set[loadbalancer.L3n4Addr]) (orphans []loadbalancer.L3n4Addr) {
	// TODO this needs to be idempotent since this operation may be retried arbitrarily many times

	newRefs := backends.Clone()
	if oldRefs, ok := s.references[frontend]; ok {
		for addr := range oldRefs {
			if newRefs.Has(addr) {
				newRefs.Delete(addr)
				continue
			}

			count := s.refCounts[addr] - 1
			if count <= 0 {
				//log.Infof("Backend %s is now an orphan", addr.StringWithProtocol())
				orphans = append(orphans, addr)
			} else {
				//log.Infof("Backend %s ref count now %d", addr.StringWithProtocol(), count)
				s.refCounts[addr] = count
			}
		}
	}
	for addr := range newRefs {
		s.refCounts[addr] = s.refCounts[addr] + 1
	}
	if len(backends) == 0 {
		delete(s.references, frontend)
	} else {
		s.references[frontend] = backends
	}
	return orphans
}

// checkBackend returns true if the backend should be updated. If the backend does not have an ID assigned to it,
// this will try to assign it.
func (s *backendsState) checkBackend(addr loadbalancer.L3n4Addr, rev statedb.Revision) (loadbalancer.BackendID, bool, error) {
	// TODO this needs to be idempotent!
	addrID, err := s.allocator.AcquireID(addr)
	if err != nil {
		return 0, false, err
	}
	if rev > s.revisions[addr] {
		return loadbalancer.BackendID(addrID.ID), true, nil
	}
	return loadbalancer.BackendID(addrID.ID), false, nil
}

func (s *backendsState) updateBackendRevision(addr loadbalancer.L3n4Addr, rev statedb.Revision) {
	s.revisions[addr] = rev
}

// releaseBackend releases the backends information and the ID when it has been deleted
// successfully.
func (s *backendsState) releaseBackend(addr loadbalancer.L3n4Addr) {
	delete(s.refCounts, addr)
	delete(s.revisions, addr)
	s.allocator.ReleaseAddr(addr)
}

func (s *backendsState) getID(addr loadbalancer.L3n4Addr) (loadbalancer.BackendID, bool) {
	if id, ok := s.allocator.GetID(addr); ok {
		return loadbalancer.BackendID(id), true
	}
	return 0, false
}

type serviceOps struct {
	backendsState *backendsState
	backends      statedb.Table[*Backend]

	numBackends map[loadbalancer.L3n4Addr]int
	allocator   *IDAllocator
}

func newServiceOps(bes statedb.Table[*Backend]) *serviceOps {
	return &serviceOps{
		backendsState: &backendsState{
			allocator:  NewIDAllocator(FirstFreeBackendID, MaxSetOfBackendID),
			revisions:  map[loadbalancer.L3n4Addr]uint64{},
			references: map[loadbalancer.L3n4Addr]sets.Set[loadbalancer.L3n4Addr]{},
			refCounts:  map[loadbalancer.L3n4Addr]int{},
		},
		backends:    bes,
		numBackends: map[loadbalancer.L3n4Addr]int{},
		allocator:   NewIDAllocator(FirstFreeServiceID, MaxSetOfServiceID),
	}
}

// Delete implements reconciler.Operations.
func (*serviceOps) Delete(context.Context, statedb.ReadTxn, *Service) error {
	panic("unimplemented")
}

// Prune implements reconciler.Operations.
func (*serviceOps) Prune(context.Context, statedb.ReadTxn, statedb.Iterator[*Service]) error {
	// TODO: prune services by dumping the map and finding any services with a frontend
	// address not found from services map.
	//
	// TODO: prune backends by dumping the map and finding any backends that are not
	// in the backends table.
	return nil
}

func sortedBackends(bes []*Backend) []*Backend {
	// TODO: this is different from the existing implementation that sorts by ID.
	// Not sure if it makes a difference.

	sort.Slice(bes, func(i, j int) bool {
		// sorting order: state, preferred, address, port
		a, b := bes[i], bes[j]
		switch {
		case a.State < b.State:
			return true
		case a.State > b.State:
			return false
		default:
			switch a.L3n4Addr.AddrCluster.Addr().Compare(b.L3n4Addr.AddrCluster.Addr()) {
			case -1:
				return true
			case 0:
				return a.L3n4Addr.Port < b.L3n4Addr.Port
			default:
				return false
			}
		}
	})
	return bes
}

func numActive(bes []*Backend) int {
	for i, be := range bes {
		if be.State != loadbalancer.BackendStateActive {
			return i
		}
	}
	return len(bes)
}

// Update implements reconciler.Operations.
func (ops *serviceOps) Update(ctx context.Context, txn statedb.ReadTxn, svc *Service, changed *bool) error {
	log.Infof("Update %s", svc.Name)

	// Gather backends for the service
	iter, _ := ops.backends.Get(txn, BackendServiceIndex.Query(svc.Name))
	backendRevisions := map[*Backend]statedb.Revision{}
	for be, rev, ok := iter.Next(); ok; be, rev, ok = iter.Next() {
		backendRevisions[be] = rev
	}
	orderedBackends := sortedBackends(maps.Keys(backendRevisions))

	// Clean up any orphan backends to make room for new backends
	backendAddrs := sets.New[loadbalancer.L3n4Addr]()
	for _, be := range orderedBackends {
		backendAddrs.Insert(be.L3n4Addr)
	}
	for _, orphan := range ops.backendsState.updateReferences(svc.L3n4Addr, backendAddrs) {
		id, ok := ops.backendsState.getID(orphan)
		if !ok {
			// FIXME unreachable?
			continue
		}
		if err := mockDeleteBackend(id); err != nil {
			return err
		}
		ops.backendsState.releaseBackend(orphan)
	}

	// Update backends that are new or changed.
	for _, be := range orderedBackends {
		rev := backendRevisions[be]
		id, update, err := ops.backendsState.checkBackend(be.L3n4Addr, rev)
		if err != nil {
			return err
		}
		if !update {
			continue
		}
		if err := mockUpdateBackend(id, be); err != nil {
			return err
		}
		ops.backendsState.updateBackendRevision(be.L3n4Addr, rev)
	}

	// Assign an identifier for the service. May fail if we have run out of IDs.
	id, err := ops.allocator.AcquireID(svc.L3n4Addr)
	if err != nil {
		return err
	}

	// Update the maglev entries: insert backend IDs into the inner
	// map and then update the outer map.
	// TODO

	// Update RevNat
	if err := mockUpdateRevNat(*id); err != nil {
		return err
	}

	// Update the master service and backend slots
	for i, be := range orderedBackends {
		if be.State != loadbalancer.BackendStateActive {
			break
		}
		beID, ok := ops.backendsState.getID(be.L3n4Addr)
		if !ok {
			// FIXME unreachable?
			panic("no ID")
		}
		if err := mockUpdateService(id.ID, svc, i+1, beID); err != nil {
			return err
		}
	}
	if err := mockUpdateService(id.ID, svc, 0, loadbalancer.BackendID(numActive(orderedBackends))); err != nil {
		return err
	}
	if err := mockCleanupSlots(id.ID, svc, ops.numBackends[svc.L3n4Addr], numActive(orderedBackends)); err != nil {
		return err
	}
	ops.numBackends[svc.L3n4Addr] = numActive(orderedBackends)

	// TODO: If *changed is nil then this is an incremental update and we should avoid
	// doing unnecessary work. Consider using e.g. bloom filter to check whether a key/value has
	// already been updated. Though it might be we really can only skip the RevNat update?

	return nil
}

var _ reconciler.Operations[*Service] = &serviceOps{}

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "services")

func mockDeleteBackend(id loadbalancer.BackendID) error {
	log.Infof("mockDeleteBackend %v", id)
	return nil
}
func mockUpdateBackend(id loadbalancer.BackendID, be *Backend) error {
	log.Infof("mockUpdateBackend %v: %s", id, be.L3n4Addr.StringWithProtocol())
	return nil
}

func mockUpdateService(id loadbalancer.ID, svc *Service, slot int, backendID loadbalancer.BackendID) error {
	log.Infof("mockUpdateService %s (%s): %d => %d", svc.Name, svc.Type, slot, backendID)
	return nil
}

func mockCleanupSlots(id loadbalancer.ID, svc *Service, old, new int) error {
	log.Infof("mockCleanupSlots %s: %d -> %d", svc.Name, old, new)
	return nil
}

func mockUpdateRevNat(addr loadbalancer.L3n4AddrID) error {
	log.Infof("mockUpdateRevNat %d -> %s:%d", addr.ID, addr.AddrCluster.Addr(), addr.Port)
	return nil
}
