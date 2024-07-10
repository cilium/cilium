// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"context"
	"log/slog"
	"sort"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"golang.org/x/exp/maps"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

// ReconcilerCell implements a mock reconciliation of the load-balancing state.
// This aims to show how to gather the relevant data for performing the reconciliation
// of the load-balancing BPF maps. The only actual work it performs is to log the
// simulated operations.
var ReconcilerCell = cell.Module(
	"reconciler",
	"Mock reconciler for load-balancing",

	cell.ProvidePrivate(newMockOps),
	cell.Invoke(registerReconciler),
)

func registerReconciler(p reconciler.Params, ops *mockOps, w *Writer) error {
	if !w.IsEnabled() {
		return nil
	}
	_, err := reconciler.Register(
		p,
		w.fes,

		(*Frontend).Clone,
		(*Frontend).setStatus,
		(*Frontend).getStatus,
		ops,
		nil,
	)
	return err
}

type mockOps struct {
	nextServiceID uint32
	log           *slog.Logger
	backendsState *backendsState
	backends      statedb.Table[*Backend]
	numBackends   map[loadbalancer.L3n4Addr]int
}

func newMockOps(log *slog.Logger, bes statedb.Table[*Backend]) *mockOps {
	return &mockOps{
		log: log,
		backendsState: &backendsState{
			backendRevision:    map[loadbalancer.L3n4Addr]uint64{},
			frontendToBackends: map[loadbalancer.L3n4Addr]sets.Set[loadbalancer.L3n4Addr]{},
			backendRefCount:    map[loadbalancer.L3n4Addr]int{},
		},
		backends:    bes,
		numBackends: map[loadbalancer.L3n4Addr]int{},
	}
}

// Delete implements reconciler.Operations.
func (ops *mockOps) Delete(ctx context.Context, txn statedb.ReadTxn, fe *Frontend) error {
	ops.log.Info("Delete frontend", "id", fe.ID, "address", fe.Address)
	return nil
}

// Prune implements reconciler.Operations.
func (ops *mockOps) Prune(context.Context, statedb.ReadTxn, statedb.Iterator[*Frontend]) error {
	ops.log.Info("Prune")
	return nil
}

// Update implements reconciler.Operations.
func (ops *mockOps) Update(ctx context.Context, txn statedb.ReadTxn, fe *Frontend) error {
	// Gather backends for the service
	iter := ops.backends.List(txn, BackendServiceIndex.Query(fe.ServiceName))
	backendRevisions := map[*Backend]statedb.Revision{}
	for be, rev, ok := iter.Next(); ok; be, rev, ok = iter.Next() {
		backendRevisions[be] = rev
	}
	orderedBackends := sortedBackends(maps.Keys(backendRevisions))

	// Clean up any orphan backends to make room for new backends
	for _, orphan := range ops.backendsState.updateReferences(fe.Address, orderedBackends) {
		ops.log.Info("Delete orphan backend", "backend", orphan)
		ops.backendsState.releaseBackend(orphan)
	}

	// Update backends that are new or changed.
	for _, be := range orderedBackends {
		rev := backendRevisions[be]
		if !ops.backendsState.needsUpdate(be.L3n4Addr, rev) {
			continue
		}
		ops.log.Info("Update backend", "backend", be)
		ops.backendsState.updateBackendRevision(be.L3n4Addr, rev)
	}

	// Assign an identifier for the service. May fail if we have run out of IDs.
	if fe.ID == 0 {
		fe.ID = loadbalancer.ID(ops.nextServiceID)
		ops.nextServiceID++
	}

	// Update RevNat
	ops.log.Info("Update RevNat", "id", fe.ID, "address", fe.Address)

	// Update the master service and backend slots
	for i, be := range orderedBackends {
		if be.State != loadbalancer.BackendStateActive {
			break
		}
		ops.log.Info("Update service", "id", fe.ID, "slot", i+1)
	}
	ops.log.Info("Update master service", "id", fe.ID)
	ops.log.Info("Cleanup service slots", "id", fe.ID, "active", numActive(orderedBackends), "previous", ops.numBackends[fe.Address])
	ops.numBackends[fe.Address] = numActive(orderedBackends)

	return nil
}

var _ reconciler.Operations[*Frontend] = &mockOps{}

// sortedBackends sorts the backends in-place with the following sort order:
// - State (active first)
// - Address
// - Port
//
// Backends are sorted to deterministically to keep the order stable in BPF maps
// when updating.
func sortedBackends(bes []*Backend) []*Backend {
	sort.Slice(bes, func(i, j int) bool {
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

// backendsState tracks what backends exist and how they're referenced by services.
type backendsState struct {
	// backendRevision is the revision of the backend last successfully reconciled.
	// Used for deciding whether the backend BPF map entry needs to be updated.
	backendRevision map[loadbalancer.L3n4Addr]statedb.Revision

	// frontendToBackends is the set of backends associated with a given frontend.
	// Used for updating 'backendRefCount'.
	frontendToBackends map[loadbalancer.L3n4Addr]sets.Set[loadbalancer.L3n4Addr]

	// backendRefCount is the number of frontends referencing a given backend.
	// Used for finding orphan backends (backends that no frontend uses and can be deleted).
	backendRefCount map[loadbalancer.L3n4Addr]int
}

func (s *backendsState) updateReferences(frontend loadbalancer.L3n4Addr, backends []*Backend) (orphans []loadbalancer.L3n4Addr) {
	newRefs := sets.New[loadbalancer.L3n4Addr]()
	for _, be := range backends {
		newRefs.Insert(be.L3n4Addr)
	}
	oldRefs := s.frontendToBackends[frontend]
	if len(backends) == 0 {
		delete(s.frontendToBackends, frontend)
	} else {
		s.frontendToBackends[frontend] = newRefs.Clone()
	}
	for addr := range oldRefs {
		if newRefs.Has(addr) {
			newRefs.Delete(addr)
			continue
		}
		count := s.backendRefCount[addr] - 1
		if count <= 0 {
			orphans = append(orphans, addr)
		} else {
			s.backendRefCount[addr] = count
		}
	}
	for addr := range newRefs {
		s.backendRefCount[addr] = s.backendRefCount[addr] + 1
	}
	return orphans
}

// checkBackend returns true if the backend should be updated.
func (s *backendsState) needsUpdate(addr loadbalancer.L3n4Addr, rev statedb.Revision) bool {
	return rev > s.backendRevision[addr]
}

func (s *backendsState) updateBackendRevision(addr loadbalancer.L3n4Addr, rev statedb.Revision) {
	s.backendRevision[addr] = rev
}

// releaseBackend releases the backends information and the ID when it has been deleted
// successfully.
func (s *backendsState) releaseBackend(addr loadbalancer.L3n4Addr) {
	delete(s.backendRefCount, addr)
	delete(s.backendRevision, addr)
}
