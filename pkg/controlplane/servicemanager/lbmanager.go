package servicemanager

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/counter"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"golang.org/x/exp/maps"
	"k8s.io/client-go/util/workqueue"
)

// FIXME this should live in pkg/datapath/loadbalancing or something.

type DatapathLoadBalancing interface { // or keep "LBMap"?
	Upsert(id ServiceID, svc *Service, backends []*Backend)
	Delete(id ServiceID)

	GarbageCollect()
}

type svcRequest struct {
	hash frontendHash
	svc *Service
	backends []*Backend
}

type backendID uint32
type backendHash = string // XXX not really a hash. (L3n4Addr.Hash)

type svcState struct {
	id uint16 // FIXME overlap with "id" in ServiceID
	backends Set[backendHash]
	// ... ?
}

type lbManager struct {
	// state is the actualized state of the service and its backends.
	state map[frontendHash]svcState

	serviceIDs map[frontendHash]uint16

	backendIDs map[backendHash]backendID
	backendRefCount counter.Counter[backendHash]

	// FIXME: need to use service.IDAllocator to deal with reuse. Move it
	// to pkg/datapath/loadbalancing.
	nextServiceID uint16
	nextBackendID backendID

	lbmap datapathTypes.LBMap
}

func (m *lbManager) restoreFromBPF() {
	// TODO:
	// - restore backendIDs and nextBackendID from DumpBackendMaps
	// - restore services? not necessarily needed.
}

func (m *lbManager) garbageCollect() {
	// TODO:
 	// - remove services from services bpf map that are not in
 	//   m.state.
 	// - remove backends that are not referenced by any services.
}

func (m *lbManager) delete(frontend loadbalancer.L3n4Addr) error {
	panic("TBD")
}

func (m *lbManager) upsert(hash frontendHash, frontend *Frontend, backends []*Backend) error {
	state, ok := m.state[hash]
	if !ok {
		state.id = m.nextServiceID
		m.nextServiceID++
	}

	// TODO: is the defer too cute? go with *svcState instead?
	defer func() {
		// Update the state based on how far we got in
		// applying the request.
		m.state[hash] = state
	}()

	// FIXME: expand the backends in the request into the
	// real set based on device IPs etc.

	// Compute the new set of backends for this service
	// and update ref counts.
	newBackends := map[backendHash]*Backend{}
	newBackendsSet := NewSet[backendHash]()
	for _, backend := range backends {
		hash := backend.Hash()
		if !state.backends.Contains(hash) {
			m.backendRefCount.Add(hash)
			newBackends[hash] = backend
			newBackendsSet.Add(hash)
		}
	}

	// Decrement refcount for removed backends.
	prevBackendsCount := len(state.backends)
	for hash := range state.backends {
		if !newBackendsSet.Contains(hash) {
			m.backendRefCount.Delete(hash)
			state.backends.Delete(hash)
		}
	}

	// Create the missing backend entries.
	missingBackends := newBackendsSet.Copy().Sub(state.backends)
	for hash := range missingBackends {
		be := newBackends[hash]
		if _, ok := m.backendIDs[hash]; !ok {
			id := m.nextBackendID

			// FIXME: change the LBMap types
			legacyBE := &loadbalancer.Backend{
				ID:         loadbalancer.BackendID(id),
				FEPortName: be.FEPortName,
				Weight:     be.Weight,
				NodeName:   be.NodeName,
				L3n4Addr:   be.L3n4Addr,
				State:      be.State,
				Preferred:  be.Preferred,
			}
			if err := m.lbmap.AddBackend(legacyBE, be.IsIPv6()); err != nil {
				return fmt.Errorf("failure while adding backend %d (%s): %w", id,
				                  be.L3n4Addr.String(), err)             
			}

			m.backendIDs[hash] = id
			m.nextBackendID++
			state.backends.Add(hash)
		}
	}

	// FIXME: We really only need the backend id and its weight, not all the data.
	// Perhaps even could update the maglev maps separately.
	legacyBackends := map[string]*loadbalancer.Backend{}
	for hash, be := range newBackends {
		legacyBE := &loadbalancer.Backend{
			ID:         loadbalancer.BackendID(m.backendIDs[hash]),
			FEPortName: be.FEPortName,
			Weight:     be.Weight,
			NodeName:   be.NodeName,
			L3n4Addr:   be.L3n4Addr,
			State:      be.State,
			Preferred:  be.Preferred,
		}
		legacyBackends[hash] = legacyBE
	}

	// Update the service entry
	params := datapathTypes.UpsertServiceParams{
		ID:                        state.id,
		IP:                        frontend.Frontend.AddrCluster.AsNetIP(),
		Port:                      frontend.Frontend.Port,
		// TODO: We need backend ID and its weight for LBMap.
		PreferredBackends:         map[string]*loadbalancer.Backend{},
		ActiveBackends:            map[string]*loadbalancer.Backend{},
		NonActiveBackends:         []loadbalancer.BackendID{},
		PrevBackendsCount:         prevBackendsCount, // Used to clean up unused slots.
		IPv6:                      frontend.Frontend.IsIPv6(),
		Type:                      frontend.Type,
		NatPolicy:                 frontend.NatPolicy,
		Local:                     false, // FIXME svcInfo.requireNodeLocalBackends
		Scope:                     frontend.Frontend.Scope,
		SessionAffinity:           frontend.SessionAffinity,
		SessionAffinityTimeoutSec: frontend.SessionAffinityTimeoutSec,
		CheckSourceRange:          false, // FIXME need to update and stuff, see service.go:1298
		UseMaglev:                 false, // FIXME depends on svc type and node port alg  (who owns this option?)
		L7LBProxyPort:             frontend.L7LBProxyPort,
		Name:                      frontend.Name,
		LoopbackHostport:          frontend.LoopbackHostport,
	}

	return m.lbmap.UpsertService(&params)
}

type frontendHash = string

// lbWorker manages the queueing and retrying of incoming
// control-plane requests
type lbWorker struct {

	m *lbManager

	unrealized map[frontendHash]*svcRequest
	wq workqueue.RateLimitingInterface

	requests chan *svcRequest
	work chan frontendHash
	gc chan struct{}
}

func (m *lbWorker) worker(ctx context.Context) {
	for {
		item, shutdown := m.wq.Get()
		if shutdown {
			return
		}
		m.work <- item.(frontendHash)
	}
}

func (w *lbWorker) processLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return

		case hash := <-w.work:
			req := w.unrealized[hash]
			var err error

			if req.svc == nil {
				err = w.m.upsert(hash, req.svc, req.backends)
			} else {
				err = w.m.delete(hash)
			}

			if err != nil {
				// TODO: Would be good to keep track of what things we're retrying and
				// what the last failure was so it can be queried. It'd be nice to have
				// structured data in the error (e.g. stuff the "WithFields" we log (lbmap.go:139)).
				w.wq.AddRateLimited(hash)
			} else {
				w.wq.Forget(hash)
				delete(w.unrealized, hash)
			}
			w.wq.Done(hash)

		case req := <-w.requests:
			w.unrealized[req.hash] = req
			w.wq.Add(req.hash)

		case <-w.gc:
			panic("TBD")
		}
	}
}

func (w *lbWorker) Upsert(svc *Service, backends ...*Backend) {
	w.requests <- &svcRequest{svc.Frontend.Hash(), svc, backends}
}

func (w *lbWorker) Delete(frontend loadbalancer.L3n4Addr) {
	w.requests <- &svcRequest{frontend.Hash(), nil, nil}
}

func (w *lbWorker) GarbageCollect() {
	w.gc <- struct{}{}
}


type Set[T comparable] map[T]struct{}

func NewSet[T comparable](items ...T) Set[T] {
	set := make(Set[T], len(items))
	for i := range items {
		set[items[i]] = struct{}{}
	}
	return set
}

func (s Set[T]) Add(item T) {
	s[item] = struct{}{}
}

func (s Set[T]) Delete(item T) {
	delete(s, item)
}

func (s Set[T]) Union(other Set[T]) Set[T] {
	for item := range other {
		s.Add(item)
	}
	return s
}

func (s Set[T]) Contains(item T) bool {
	_, ok := s[item]
	return ok
}

func (s Set[T]) Copy() Set[T] {
	return NewSet[T](maps.Keys(s)...)
}

func (s Set[T]) Sub(other Set[T]) Set[T] {
	for item := range other {
		delete(s, item)
	}
	return s
}

func (s Set[T]) Diff(other Set[T]) Set[T] {
	diff := NewSet[T]()
	for item := range other {
		if !s.Contains(item) {
			diff.Add(item)
		}
	}
	for item := range s {
		if !other.Contains(item) {
			diff.Add(item)
		}
	}
	return diff
}

